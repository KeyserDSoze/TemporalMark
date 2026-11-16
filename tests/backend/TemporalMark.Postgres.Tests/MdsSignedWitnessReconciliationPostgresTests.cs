using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// RED-first offline, disposable RSA-PSS signed snapshot reconciliation on a
/// real PostgreSQL V017 scope. A test key is NOT an approved external witness.
/// </summary>
public sealed class MdsSignedWitnessReconciliationPostgresTests
{
    private const string Domain = "TEMPORALMARK-UNAPPROVED-MDS-CRL-WITNESS-1";

    private static NpgsqlConnection Owner() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_TEST_DB missing"));

    private static NpgsqlConnection Approver() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_APPROVER_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_APPROVER_TEST_DB missing"));

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private sealed record Candidate(string Kind, string Issuer, string Policy,
        long Serial, string Digest)
    {
        public static Candidate Fresh(string? policy = null, string kind = "MDS_BLOB") =>
            new(kind, Hash("issuer-" + Guid.NewGuid()),
                policy ?? Hash("source-" + Guid.NewGuid()),
                7, Hash("contents-" + Guid.NewGuid()));

        public string Line => string.Join("|",
            Kind, Issuer, Serial.ToString(CultureInfo.InvariantCulture), Digest);
    }

    private static async Task Stage(NpgsqlConnection db, Candidate candidate)
    {
        await using var cmd = new NpgsqlCommand("""
            SELECT public.record_unapproved_mds_checkpoint_candidate(
                @kind,@issuer,@serial,@digest,@policy,3600,'CAB-TEST-WITNESS')
            """, db);
        cmd.Parameters.AddWithValue("kind", candidate.Kind);
        cmd.Parameters.AddWithValue("issuer", candidate.Issuer);
        cmd.Parameters.AddWithValue("serial", candidate.Serial);
        cmd.Parameters.AddWithValue("digest", candidate.Digest);
        cmd.Parameters.AddWithValue("policy", candidate.Policy);
        Assert.Equal("UNAPPROVED", await cmd.ExecuteScalarAsync());
    }

    private static byte[] Manifest(string policy, DateTimeOffset now,
        IEnumerable<string> entryLines,
        DateTimeOffset? issued = null, DateTimeOffset? expiry = null)
    {
        var entries = entryLines.ToArray();
        var text = string.Join("\n", new[]
        {
            Domain, policy,
            (issued ?? now.AddSeconds(-5)).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            (expiry ?? now.AddMinutes(10)).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            entries.Length.ToString(CultureInfo.InvariantCulture)
        }.Concat(entries)) + "\n";
        return Encoding.ASCII.GetBytes(text);
    }

    private static byte[] Sign(RSA key, byte[] manifest) =>
        key.SignData(manifest, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    private static Task<ReviewerMdsSignedWitnessCandidate> Check(
        NpgsqlConnection db, RSA key, byte[]? manifest, byte[]? signature,
        DateTimeOffset now) =>
        ReviewerMdsOfflineSignedCheckpointWitnessReconciler.ReconcileAsync(
            db, manifest, signature, key, now);

    [Fact]
    public async Task ActualSignedTwoCandidateScopedSnapshotIsOnlyUnapprovedObservation()
    {
        var policy = Hash("policy-" + Guid.NewGuid());
        var a = Candidate.Fresh(policy, "ISSUER_CRL");
        var b = Candidate.Fresh(policy, "MDS_BLOB");
        await using var db = Owner();
        await db.OpenAsync();
        await Stage(db, a);
        await Stage(db, b);

        using var key = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var manifest = Manifest(policy, now, [a.Line, b.Line]);
        var observation = await Check(db, key, manifest, Sign(key, manifest), now);

        Assert.Equal("UNAPPROVED", observation.ReviewStatus);
        Assert.Equal("SIGNED_WITNESS_ONLY_EXTERNAL_CUSTODY_UNPROVEN", observation.PolicyStage);
        Assert.Equal(2, observation.MatchedCandidates);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(manifest)), observation.WitnessSha256);
        Assert.DoesNotContain(typeof(ReviewerMdsSignedWitnessCandidate).GetProperties(),
            p => p.Name.Contains("Trusted", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("Approved", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("Active", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("PublicKey", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task TamperingMissingOrWrongWitnessSignatureNeverBecomesAValidCheckpoint()
    {
        var c = Candidate.Fresh();
        await using var db = Owner();
        await db.OpenAsync();
        await Stage(db, c);
        using var key = RSA.Create(2048);
        using var attacker = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var manifest = Manifest(c.Policy, now, [c.Line]);
        var signature = Sign(key, manifest);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, attacker, manifest, signature, now));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, key, manifest, Sign(attacker, manifest), now));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, key, manifest, null, now));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, key, null, signature, now));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, key, manifest, [], now));
        var forged = manifest.ToArray();
        forged[forged.Length - 2] ^= 1;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, key, forged, signature, now));
    }

    [Fact]
    public async Task RestoredLowerDatabaseSerialAndEqualVersionContentEquivocationAreRejected()
    {
        var c = Candidate.Fresh(kind: "ISSUER_CRL");
        await using var db = Owner();
        await db.OpenAsync();
        await Stage(db, c with { Serial = 6, Digest = Hash("older") });
        await Stage(db, c);
        using var key = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var manifest = Manifest(c.Policy, now, [c.Line]);
        var signature = Sign(key, manifest);

        Assert.Equal("UNAPPROVED",
            (await Check(db, key, manifest, signature, now)).ReviewStatus);

        // Migration-owner test simulates stale backup contents. This is not
        // actual backup restoration or a separately preserved witness store.
        await using (var regress = new NpgsqlCommand("""
            UPDATE public.mds_unapproved_candidate_checkpoints
            SET candidate_serial=6,signed_evidence_sha256=@digest
            WHERE candidate_kind=@kind AND issuer_key_sha256=@issuer
            """, db))
        {
            regress.Parameters.AddWithValue("digest", Hash("older"));
            regress.Parameters.AddWithValue("kind", c.Kind);
            regress.Parameters.AddWithValue("issuer", c.Issuer);
            Assert.Equal(1, await regress.ExecuteNonQueryAsync());
        }

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, key, manifest, signature, now));
        await using (var change = new NpgsqlCommand("""
            UPDATE public.mds_unapproved_candidate_checkpoints
            SET candidate_serial=7,signed_evidence_sha256=@digest
            WHERE candidate_kind=@kind AND issuer_key_sha256=@issuer
            """, db))
        {
            change.Parameters.AddWithValue("digest", Hash("equivocated"));
            change.Parameters.AddWithValue("kind", c.Kind);
            change.Parameters.AddWithValue("issuer", c.Issuer);
            await change.ExecuteNonQueryAsync();
        }
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, key, manifest, signature, now));
    }

    [Fact]
    public async Task MissingExtraOrNewerDatabaseRowsFailClosedWithinExactWitnessScope()
    {
        var policy = Hash("policy-" + Guid.NewGuid());
        var first = Candidate.Fresh(policy);
        var second = Candidate.Fresh(policy, "ISSUER_CRL");
        await using var db = Owner();
        await db.OpenAsync();
        await Stage(db, first);
        using var key = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var one = Manifest(policy, now, [first.Line]);
        var oneSig = Sign(key, one);
        Assert.Equal("UNAPPROVED", (await Check(db, key, one, oneSig, now)).ReviewStatus);

        await Stage(db, second);
        // An extra row in the same source-policy scope rejects an old witness.
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, key, one, oneSig, now));
        // The second V017 row was observed after the first witness clock.\n        // Take a fresh trusted test observation before signing the NEW scope.\n        now = DateTimeOffset.UtcNow;\n        var both = Manifest(policy, now, [second.Line, first.Line]);
        var bothSig = Sign(key, both);
        Assert.Equal("UNAPPROVED",
            (await Check(db, key, both, bothSig, now)).ReviewStatus);

        await using (var remove = new NpgsqlCommand("""
            DELETE FROM public.mds_unapproved_candidate_checkpoints
            WHERE candidate_kind=@kind AND issuer_key_sha256=@issuer
            """, db))
        {
            remove.Parameters.AddWithValue("kind", second.Kind);
            remove.Parameters.AddWithValue("issuer", second.Issuer);
            Assert.Equal(1, await remove.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, key, both, bothSig, now));

        var newer = first with { Serial = 8, Digest = Hash("newer") };
        await Stage(db, newer);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, key, one, oneSig, now));
    }

    [Fact]
    public async Task SignedButInvalidOrAmbiguousManifestIsDeniedBeforeDatabaseRead()
    {
        var c = Candidate.Fresh();
        await using var db = Owner();
        await db.OpenAsync();
        await Stage(db, c);
        using var key = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;

        var invalid = new[]
        {
            Manifest(c.Policy, now, [c.Line, c.Line]), // duplicate
            Manifest(c.Policy, now, [c.Line, "ISSUER_CRL|" + c.Issuer + "|2|" + c.Digest]),
            Manifest(c.Policy, now, ["MDS_BLOB|" + c.Issuer + "|07|" + c.Digest]),
            Manifest(c.Policy, now, ["TRUSTED|" + c.Issuer + "|7|" + c.Digest]),
            Manifest("invalid", now, [c.Line]),
            Manifest(c.Policy.ToLowerInvariant(), now, [c.Line]),
            Manifest(c.Policy, now, [c.Line], issued: now.AddMinutes(1)),
            Manifest(c.Policy, now, [c.Line], expiry: now.AddSeconds(-2)),
            Manifest(c.Policy, now, [c.Line], expiry: now.AddDays(3)),
            Encoding.UTF8.GetBytes("unknown-domain\n" + c.Policy + "\n1\n2\n1\n" + c.Line + "\n"),
            [.. Manifest(c.Policy, now, [c.Line]), 0x00],
            Encoding.UTF8.GetBytes(Encoding.ASCII.GetString(Manifest(c.Policy, now, [c.Line])).Replace("\n", "\r\n")),
            new byte[66_000]
        };
        foreach (var candidate in invalid)
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                Check(db, key, candidate, Sign(key, candidate), now));
    }

    [Fact]
    public async Task ExpiredDbSnapshotOrUnprivilegedSqlReaderMustNotReconcile()
    {
        var c = Candidate.Fresh();
        await using var owner = Owner();
        await owner.OpenAsync();
        await Stage(owner, c);
        using var key = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var manifest = Manifest(c.Policy, now, [c.Line]);
        var signature = Sign(key, manifest);

        await using var approver = Approver();
        await approver.OpenAsync();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(approver, key, manifest, signature, now));

        // Simulate a validly formed but expired V017 DB record as an owner.
        await using (var cmd = new NpgsqlCommand("""
            UPDATE public.mds_unapproved_candidate_checkpoints
            SET observed_utc=clock_timestamp()-interval '2 hours',
                expires_utc=clock_timestamp()-interval '1 hour'
            WHERE candidate_kind=@kind AND issuer_key_sha256=@issuer
            """, owner))
        {
            cmd.Parameters.AddWithValue("kind", c.Kind);
            cmd.Parameters.AddWithValue("issuer", c.Issuer);
            Assert.Equal(1, await cmd.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(owner, key, manifest, signature, now));
    }
}
