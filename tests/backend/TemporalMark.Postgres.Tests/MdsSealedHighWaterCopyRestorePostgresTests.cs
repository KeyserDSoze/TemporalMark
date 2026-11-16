using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// RED-first scoped PostgreSQL COPY export/import rollback with separately
/// signed, disposable *test* witness and high-water seal. The externally
/// retained latest hash is a test assertion, NOT independent production
/// immutable custody or trusted FIDO root.
/// </summary>
public sealed class MdsSealedHighWaterCopyRestorePostgresTests
{
    private const string WitnessDomain = "TEMPORALMARK-UNAPPROVED-MDS-CRL-WITNESS-1";
    private const string SealDomain = "TEMPORALMARK-UNAPPROVED-EXTERNAL-WITNESS-SEAL-1";
    private const string Columns = "candidate_kind,issuer_key_sha256,source_policy_sha256,candidate_serial,signed_evidence_sha256,change_reference,observed_utc,expires_utc,review_status";

    private static NpgsqlConnection Owner() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_TEST_DB missing"));

    private static NpgsqlConnection Approver() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_APPROVER_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_APPROVER_TEST_DB missing"));

    private static string Hash(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private sealed record Scope(string Policy, string Issuer)
    {
        public static Scope Fresh() =>
            new(Hash("seal-test-policy-" + Guid.NewGuid()), Hash("seal-test-issuer-" + Guid.NewGuid()));

        public string Line(long version, string digest) =>
            "MDS_BLOB|" + Issuer + "|" +
            version.ToString(CultureInfo.InvariantCulture) + "|" + digest;
    }

    private static async Task Stage(NpgsqlConnection connection, Scope scope,
        long version, string evidenceHash)
    {
        await using var cmd = new NpgsqlCommand("""
            SELECT public.record_unapproved_mds_checkpoint_candidate(
                'MDS_BLOB',@issuer,@serial,@digest,@policy,3600,'CAB-TEST-SEALED-HIGHWATER')
            """, connection);
        cmd.Parameters.AddWithValue("issuer", scope.Issuer);
        cmd.Parameters.AddWithValue("serial", version);
        cmd.Parameters.AddWithValue("digest", evidenceHash);
        cmd.Parameters.AddWithValue("policy", scope.Policy);
        Assert.Equal("UNAPPROVED", await cmd.ExecuteScalarAsync());
    }

    private static byte[] Witness(Scope scope, long version,
        string evidenceHash, DateTimeOffset now) =>
        Encoding.ASCII.GetBytes(string.Join("\n",
        [
            WitnessDomain, scope.Policy,
            now.AddSeconds(-10).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            now.AddMinutes(10).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            "1", scope.Line(version, evidenceHash), ""
        ]));

    private static byte[] Seal(Scope scope, byte[] witness, DateTimeOffset now) =>
        Encoding.ASCII.GetBytes(string.Join("\n",
        [
            SealDomain, scope.Policy, Convert.ToHexString(SHA256.HashData(witness)),
            now.AddSeconds(-10).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            now.AddMinutes(10).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ""
        ]));

    private static byte[] Sign(RSA key, byte[] body) =>
        key.SignData(body, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

    private static string SpkiPin(RSA key) =>
        Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));

    private static Task<ReviewerMdsSealedHighWaterCandidate> Check(
        NpgsqlConnection database, RSA witnessKey, RSA sealKey, byte[] witness,
        byte[] seal, DateTimeOffset now, string? latestSealPin = null,
        string? sealAuthorityPin = null, byte[]? sealSignature = null,
        byte[]? witnessSignature = null) =>
        ReviewerMdsOfflineSealedHighWaterCandidateVerifier.ReconcileAsync(
            database, witness, witnessSignature ?? Sign(witnessKey, witness),
            witnessKey, seal, sealSignature ?? Sign(sealKey, seal), sealKey,
            sealAuthorityPin ?? SpkiPin(sealKey),
            latestSealPin ?? Convert.ToHexString(SHA256.HashData(seal)), now);

    [Fact]
    public async Task SeparatelySignedLatestSealIsOnlyUnapprovedTestObservation()
    {
        var scope = Scope.Fresh();
        var digest = Hash("initial-" + Guid.NewGuid());
        await using var db = Owner();
        await db.OpenAsync();
        await Stage(db, scope, 4, digest);
        using var signer = RSA.Create(2048);
        using var externalSealSigner = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var witness = Witness(scope, 4, digest, now);
        var seal = Seal(scope, witness, now);

        var result = await Check(db, signer, externalSealSigner, witness, seal, now);
        Assert.Equal("UNAPPROVED", result.ReviewStatus);
        Assert.Equal("TEST_HIGH_WATER_SEAL_EXTERNAL_CUSTODY_UNPROVEN", result.PolicyStage);
        Assert.Equal(1, result.MatchedCandidates);
        Assert.Equal(Hash(Convert.ToHexString(witness)), Hash(result.WitnessSha256));
        Assert.Equal(Convert.ToHexString(SHA256.HashData(seal)), result.SealSha256);
        Assert.DoesNotContain(typeof(ReviewerMdsSealedHighWaterCandidate).GetProperties(),
            p => p.Name.Contains("Trusted", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("ApprovedSigner", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("Active", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("PublicKey", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ActualPostgresqlCopyExportAndRestoreCannotBypassRetainedLatestSealHash()
    {
        var scope = Scope.Fresh();
        var oldDigest = Hash("copy-old-" + Guid.NewGuid());
        var latestDigest = Hash("copy-latest-" + Guid.NewGuid());
        await using var db = Owner();
        await db.OpenAsync();
        await Stage(db, scope, 3, oldDigest);

        // Real PostgreSQL COPY TO STDOUT snapshot of one disposable V017
        // source-policy scope, retained in test memory OUTSIDE PostgreSQL.
        // This is NOT full pg_dump or production backup/restore validation.
        string backupCsv;
        using (var reader = db.BeginTextExport(
            $"COPY (SELECT {Columns} FROM public.mds_unapproved_candidate_checkpoints WHERE source_policy_sha256='{scope.Policy}') TO STDOUT (FORMAT CSV)"))
            backupCsv = reader.ReadToEnd();
        Assert.Contains(scope.Policy, backupCsv);

        using var witnessSigner = RSA.Create(2048);
        using var externalSealSigner = RSA.Create(2048);
        var oldNow = DateTimeOffset.UtcNow;
        var oldWitness = Witness(scope, 3, oldDigest, oldNow);
        var oldSeal = Seal(scope, oldWitness, oldNow);

        await Stage(db, scope, 4, latestDigest);
        var newestNow = DateTimeOffset.UtcNow;
        var newestWitness = Witness(scope, 4, latestDigest, newestNow);
        var newestSeal = Seal(scope, newestWitness, newestNow);
        var externallyRetainedLatestSealSha256 =
            Convert.ToHexString(SHA256.HashData(newestSeal));

        Assert.Equal("UNAPPROVED", (await Check(db, witnessSigner, externalSealSigner,
            newestWitness, newestSeal, newestNow,
            latestSealPin: externallyRetainedLatestSealSha256)).ReviewStatus);

        // Real PostgreSQL COPY FROM STDIN restores the old candidate DATA.
        // Tests run as migration owner, no production privilege or full
        // cluster restore. The latest seal pin remains OUTSIDE the DB.
        await using (var delete = new NpgsqlCommand("""
            DELETE FROM public.mds_unapproved_candidate_checkpoints
            WHERE source_policy_sha256=@policy
            """, db))
        {
            delete.Parameters.AddWithValue("policy", scope.Policy);
            Assert.Equal(1, await delete.ExecuteNonQueryAsync());
        }
        using (var writer = db.BeginTextImport(
            $"COPY public.mds_unapproved_candidate_checkpoints ({Columns}) FROM STDIN (FORMAT CSV)"))
            writer.Write(backupCsv);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, externalSealSigner, newestWitness, newestSeal,
                newestNow, latestSealPin: externallyRetainedLatestSealSha256));

        // Both witness and seal WERE correctly signed in the past.
        // The independently retained NEW seal digest prevents replay.
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, externalSealSigner, oldWitness, oldSeal,
                newestNow, latestSealPin: externallyRetainedLatestSealSha256));

        // Critical unmitigated attack: substituting the OUT-OF-BAND latest
        // pin together with the old backup makes the old pair appear valid.
        // This must stay UNAPPROVED; real immutable custody is #64.
        Assert.Equal("UNAPPROVED", (await Check(db, witnessSigner,
            externalSealSigner, oldWitness, oldSeal, newestNow,
            latestSealPin: Convert.ToHexString(SHA256.HashData(oldSeal)))).ReviewStatus);
    }

    [Fact]
    public async Task IncorrectPinsSignatureAndDifferentSealAuthorityFailClosed()
    {
        var scope = Scope.Fresh();
        var digest = Hash("pin-fixture-" + Guid.NewGuid());
        await using var db = Owner();
        await db.OpenAsync();
        await Stage(db, scope, 5, digest);
        using var witnessSigner = RSA.Create(2048);
        using var sealSigner = RSA.Create(2048);
        using var attacker = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var witness = Witness(scope, 5, digest, now);
        var seal = Seal(scope, witness, now);
        var correctAuthorityPin = SpkiPin(sealSigner);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, sealSigner, witness, seal, now,
                latestSealPin: Hash("previous-seal")));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, sealSigner, witness, seal, now,
                sealAuthorityPin: SpkiPin(attacker)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, attacker, witness, seal, now,
                sealAuthorityPin: correctAuthorityPin));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, sealSigner, witness, seal, now,
                sealSignature: Sign(attacker, seal)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, sealSigner, witness, seal, now,
                witnessSignature: Sign(attacker, witness)));
        var tampered = seal.ToArray();
        tampered[^2] ^= 1;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, sealSigner, witness, tampered, now,
                latestSealPin: Convert.ToHexString(SHA256.HashData(seal))));
    }

    [Fact]
    public async Task SignedNonCanonicalStaleMissingOrWrongScopeSealIsDenied()
    {
        var scope = Scope.Fresh();
        var digest = Hash("canonical-fixture-" + Guid.NewGuid());
        await using var db = Owner();
        await db.OpenAsync();
        await Stage(db, scope, 6, digest);
        using var witnessSigner = RSA.Create(2048);
        using var sealSigner = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var witness = Witness(scope, 6, digest, now);
        var seal = Seal(scope, witness, now);
        var valid = Encoding.ASCII.GetString(seal);
        var lines = valid.Split('\n');
        var malformed = new[]
        {
            Encoding.ASCII.GetBytes(valid.Replace("\n", "\r\n")),
            Encoding.ASCII.GetBytes(valid.Replace(SealDomain, "WRONG-DOMAIN")),
            Encoding.ASCII.GetBytes(valid.Replace(scope.Policy, Hash("wrong-scope"))),
            Encoding.ASCII.GetBytes(valid.Replace(lines[2], Hash("wrong-witness"))),
            Encoding.ASCII.GetBytes(valid.Replace("\n"+lines[3]+"\n", "\n0"+lines[3]+"\n")),
            Encoding.ASCII.GetBytes(valid.Replace("\n"+lines[4]+"\n", "\n0"+lines[4]+"\n")),
            Encoding.ASCII.GetBytes(valid + "\n"),
            [.. seal, 0x00],
            new byte[4097]
        };
        foreach (var malformedSeal in malformed)
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                Check(db, witnessSigner, sealSigner, witness, malformedSeal, now));

        var future = Seal(scope, witness, now.AddMinutes(2));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, sealSigner, witness, future, now));

        var expired = Seal(scope, witness, now.AddDays(-1));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, sealSigner, witness, expired, now));

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, sealSigner, witness, seal, now,
                latestSealPin: ""));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, sealSigner, witness, seal, now,
                sealAuthorityPin: ""));
    }

    [Fact]
    public async Task EqualSerialAlteredCheckpointAndUnprivilegedReaderCannotPassSealedWitness()
    {
        var scope = Scope.Fresh();
        var digest = Hash("equivocation-" + Guid.NewGuid());
        await using var db = Owner();
        await db.OpenAsync();
        await Stage(db, scope, 8, digest);
        using var witnessSigner = RSA.Create(2048);
        using var sealSigner = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var witness = Witness(scope, 8, digest, now);
        var seal = Seal(scope, witness, now);

        await using var approver = Approver();
        await approver.OpenAsync();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(approver, witnessSigner, sealSigner, witness, seal, now));

        await using var change = new NpgsqlCommand("""
            UPDATE public.mds_unapproved_candidate_checkpoints
            SET signed_evidence_sha256=@changed
            WHERE source_policy_sha256=@policy
            """, db);
        change.Parameters.AddWithValue("changed", Hash("alternative-evidence"));
        change.Parameters.AddWithValue("policy", scope.Policy);
        Assert.Equal(1, await change.ExecuteNonQueryAsync());

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(db, witnessSigner, sealSigner, witness, seal, now));
    }
}
