using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// RED-first LIVE PostgreSQL tests for a never-authorizing, migration-owner
/// candidate version checkpoint. The caller-supplied hashes are UNTRUSTED:
/// a valid SQL row is NOT proof of FIDO/JWS/CRL signatures or immutable backup.
/// </summary>
public sealed class MdsUnapprovedCheckpointPostgresTests
{
    private static NpgsqlConnection Owner() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_TEST_DB missing"));
    private static NpgsqlConnection Approver() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_APPROVER_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_APPROVER_TEST_DB missing"));
    private static NpgsqlConnection Provisioner() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_PROVISIONING_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_PROVISIONING_TEST_DB missing"));

    private static string Hash(string text) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private sealed record Candidate(string Kind, string Issuer, string Policy, string Change)
    {
        public static Candidate Fresh(string kind = "MDS_BLOB")
        {
            var suffix = Guid.NewGuid().ToString("N");
            return new Candidate(kind, Hash("test-issuer-" + suffix),
                Hash("test-source-policy-" + suffix), "CAB-TEST-" + suffix);
        }

        public string Digest(long version) => Hash("untrusted-synthetic-" + Issuer + "-" + version);
    }

    private static async Task<string> StageAsync(
        NpgsqlConnection db, Candidate c, long serial,
        string? digest = null, string? policy = null,
        int ttlSeconds = 3600, string? kind = null,
        string? issuer = null, string? change = null)
    {
        await using var cmd = new NpgsqlCommand("""
            SELECT public.record_unapproved_mds_checkpoint_candidate(
                @kind,@issuer,@serial,@digest,@policy,@ttl,@change)
            """, db);
        cmd.Parameters.AddWithValue("kind", kind ?? c.Kind);
        cmd.Parameters.AddWithValue("issuer", issuer ?? c.Issuer);
        cmd.Parameters.AddWithValue("serial", serial);
        cmd.Parameters.AddWithValue("digest", digest ?? c.Digest(serial));
        cmd.Parameters.AddWithValue("policy", policy ?? c.Policy);
        cmd.Parameters.AddWithValue("ttl", ttlSeconds);
        cmd.Parameters.AddWithValue("change", change ?? c.Change);
        return Assert.IsType<string>(await cmd.ExecuteScalarAsync());
    }

    private static async Task<(long Version, string Digest, DateTime Expires)> CurrentAsync(
        NpgsqlConnection db, Candidate c)
    {
        await using var cmd = new NpgsqlCommand("""
            SELECT candidate_serial,signed_evidence_sha256,expires_utc
            FROM public.mds_unapproved_candidate_checkpoints
            WHERE candidate_kind=@kind AND issuer_key_sha256=@issuer
            """, db);
        cmd.Parameters.AddWithValue("kind", c.Kind);
        cmd.Parameters.AddWithValue("issuer", c.Issuer);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        var value = (reader.GetInt64(0), reader.GetString(1), reader.GetDateTime(2));
        Assert.False(await reader.ReadAsync());
        return value;
    }

    private static async Task<long> HistoryAsync(NpgsqlConnection db, Candidate c)
    {
        await using var cmd = new NpgsqlCommand("""
            SELECT count(*) FROM public.mds_unapproved_candidate_events
            WHERE candidate_kind=@kind AND issuer_key_sha256=@issuer
            """, db);
        cmd.Parameters.AddWithValue("kind", c.Kind);
        cmd.Parameters.AddWithValue("issuer", c.Issuer);
        return Assert.IsType<long>(await cmd.ExecuteScalarAsync());
    }

    [Fact]
    public async Task FirstCandidateAndEqualVersionSameDigestRemainUnapprovedWithoutRefreshingExpiry()
    {
        var c = Candidate.Fresh();
        await using var db = Owner();
        await db.OpenAsync();
        Assert.Equal("UNAPPROVED", await StageAsync(db, c, 4));
        var first = await CurrentAsync(db, c);
        Assert.Equal(4L, first.Version);
        Assert.Equal(c.Digest(4), first.Digest);
        Assert.Equal(1L, await HistoryAsync(db, c));

        // Equal signed version+digest+policy is purely idempotent, and must
        // NOT extend a candidate's TTL or append fabricated evidence.
        Assert.Equal("UNAPPROVED", await StageAsync(db, c, 4, ttlSeconds: 86400));
        var again = await CurrentAsync(db, c);
        Assert.Equal(first, again);
        Assert.Equal(1L, await HistoryAsync(db, c));
    }

    [Fact]
    public async Task LowerSerialOrSameSerialDifferentContentOrSourceCannotReplaceCheckpoint()
    {
        var c = Candidate.Fresh("ISSUER_CRL");
        await using var db = Owner();
        await db.OpenAsync();
        Assert.Equal("UNAPPROVED", await StageAsync(db, c, 7));
        await Assert.ThrowsAsync<PostgresException>(() => StageAsync(db, c, 6));
        await Assert.ThrowsAsync<PostgresException>(() =>
            StageAsync(db, c, 7, digest: Hash("different-revocation-list")));
        await Assert.ThrowsAsync<PostgresException>(() =>
            StageAsync(db, c, 7, policy: Hash("unapproved-new-issuer-source")));
        Assert.Equal(7L, (await CurrentAsync(db, c)).Version);
        Assert.Equal(1L, await HistoryAsync(db, c));

        Assert.Equal("UNAPPROVED", await StageAsync(db, c, 8));
        Assert.Equal(8L, (await CurrentAsync(db, c)).Version);
        Assert.Equal(2L, await HistoryAsync(db, c));
        await Assert.ThrowsAsync<PostgresException>(() => StageAsync(db, c, 7));
        await Assert.ThrowsAsync<PostgresException>(() =>
            StageAsync(db, c, 9, policy: Hash("unapproved-new-issuer-source")));
        Assert.Equal(2L, await HistoryAsync(db, c));
    }

    [Fact]
    public async Task EvidenceKindsAndUnrelatedIssuerIdentifiersHaveIndependentVersionLines()
    {
        var first = Candidate.Fresh();
        var crl = first with { Kind = "ISSUER_CRL" };
        var other = Candidate.Fresh();
        await using var db = Owner();
        await db.OpenAsync();
        Assert.Equal("UNAPPROVED", await StageAsync(db, first, 42));
        Assert.Equal("UNAPPROVED", await StageAsync(db, crl, 2));
        Assert.Equal("UNAPPROVED", await StageAsync(db, other, 1));
        Assert.Equal(42L, (await CurrentAsync(db, first)).Version);
        Assert.Equal(2L, (await CurrentAsync(db, crl)).Version);
        Assert.Equal(1L, (await CurrentAsync(db, other)).Version);
    }

    [Fact]
    public async Task MissingMalformedOrOversizedOwnerInputsAreDeniedWithoutCreatingAnyCandidate()
    {
        var c = Candidate.Fresh();
        await using var db = Owner();
        await db.OpenAsync();
        foreach (var attempt in new Func<Task>[]
        {
            () => StageAsync(db, c, 0),
            () => StageAsync(db, c, -1),
            () => StageAsync(db, c, 1, kind: "TRUSTED"),
            () => StageAsync(db, c, 1, issuer: "lowercase"),
            () => StageAsync(db, c, 1, issuer: new string('F', 65)),
            () => StageAsync(db, c, 1, digest: new string('Z', 64)),
            () => StageAsync(db, c, 1, policy: "incomplete"),
            () => StageAsync(db, c, 1, ttlSeconds: 0),
            () => StageAsync(db, c, 1, ttlSeconds: 86401),
            () => StageAsync(db, c, 1, change: ""),
            () => StageAsync(db, c, 1, change: new string('a', 129))
        })
            await Assert.ThrowsAsync<PostgresException>(attempt);
        Assert.Equal("UNAPPROVED", await StageAsync(db, c, 1));
        Assert.Equal(1L, await HistoryAsync(db, c));
    }

    [Fact]
    public async Task ExpiredOrFutureDatedCheckpointFailsClosedEvenForLaterRevision()
    {
        var c = Candidate.Fresh();
        await using var db = Owner();
        await db.OpenAsync();
        Assert.Equal("UNAPPROVED", await StageAsync(db, c, 2));
        // Owner-only test simulates a stale backup/clock anomaly. It does
        // NOT prove that a real DB restore could be detected automatically.
        await using (var simulate = new NpgsqlCommand("""
            UPDATE public.mds_unapproved_candidate_checkpoints
            SET observed_utc=clock_timestamp()-interval '2 hours',
                expires_utc=clock_timestamp()-interval '1 hour'
            WHERE candidate_kind=@kind AND issuer_key_sha256=@issuer
            """, db))
        {
            simulate.Parameters.AddWithValue("kind", c.Kind);
            simulate.Parameters.AddWithValue("issuer", c.Issuer);
            Assert.Equal(1, await simulate.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<PostgresException>(() => StageAsync(db, c, 3));
        await Assert.ThrowsAsync<PostgresException>(() => StageAsync(db, c, 2));
        Assert.Equal(2L, (await CurrentAsync(db, c)).Version);
        Assert.Equal(1L, await HistoryAsync(db, c));

        var later = Candidate.Fresh("ISSUER_CRL");
        Assert.Equal("UNAPPROVED", await StageAsync(db, later, 3));
        await using (var simulate = new NpgsqlCommand("""
            UPDATE public.mds_unapproved_candidate_checkpoints
            SET observed_utc=clock_timestamp()+interval '5 minutes'
            WHERE candidate_kind=@kind AND issuer_key_sha256=@issuer
            """, db))
        {
            simulate.Parameters.AddWithValue("kind", later.Kind);
            simulate.Parameters.AddWithValue("issuer", later.Issuer);
            await simulate.ExecuteNonQueryAsync();
        }
        await Assert.ThrowsAsync<PostgresException>(() => StageAsync(db, later, 4));
    }

    [Fact]
    public async Task CheckpointHistoryIsOwnerOnlyAndAppendOnlyByNormalSqlTrigger()
    {
        var c = Candidate.Fresh();
        await using var db = Owner();
        await db.OpenAsync();
        Assert.Equal("UNAPPROVED", await StageAsync(db, c, 1));
        await using (var change = new NpgsqlCommand("""
            UPDATE public.mds_unapproved_candidate_events
            SET candidate_serial=9 WHERE candidate_kind=@kind AND issuer_key_sha256=@issuer
            """, db))
        {
            change.Parameters.AddWithValue("kind", c.Kind);
            change.Parameters.AddWithValue("issuer", c.Issuer);
            var ex = await Assert.ThrowsAsync<PostgresException>(
                async () => await change.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
        }
        await using (var delete = new NpgsqlCommand("""
            DELETE FROM public.mds_unapproved_candidate_events
            WHERE candidate_kind=@kind AND issuer_key_sha256=@issuer
            """, db))
        {
            delete.Parameters.AddWithValue("kind", c.Kind);
            delete.Parameters.AddWithValue("issuer", c.Issuer);
            var ex = await Assert.ThrowsAsync<PostgresException>(
                async () => await delete.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.CheckViolation, ex.SqlState);
        }
        Assert.Equal(1L, await HistoryAsync(db, c));
    }

    [Fact]
    public async Task RuntimeRegistrarProvisionerAndApproverCannotReadOrStageCandidate()
    {
        await using var owner = Owner();
        await owner.OpenAsync();
        await using (var query = new NpgsqlCommand("""
            SELECT r.rolname,
              has_function_privilege(r.rolname,
                'public.record_unapproved_mds_checkpoint_candidate(text,text,bigint,text,text,integer,text)',
                'EXECUTE'),
              has_table_privilege(r.rolname,
                'public.mds_unapproved_candidate_checkpoints','SELECT'),
              has_table_privilege(r.rolname,
                'public.mds_unapproved_candidate_events','INSERT')
            FROM pg_catalog.pg_roles AS r
            WHERE r.rolname IN ('temporalmark_runtime_group',
              'temporalmark_provisioner_group','temporalmark_approver_group',
              'temporalmark_credential_registrar_group')
            ORDER BY r.rolname
            """, owner))
        await using (var reader = await query.ExecuteReaderAsync())
        {
            var count = 0;
            while (await reader.ReadAsync())
            {
                count++;
                Assert.False(reader.GetBoolean(1));
                Assert.False(reader.GetBoolean(2));
                Assert.False(reader.GetBoolean(3));
            }
            Assert.Equal(4, count);
        }

        var c = Candidate.Fresh();
        foreach (var connection in new[] { Approver(), Provisioner() })
        {
            await using (connection)
            {
                await connection.OpenAsync();
                var error = await Assert.ThrowsAsync<PostgresException>(() =>
                    StageAsync(connection, c, 1));
                Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, error.SqlState);
                await using var read = new NpgsqlCommand(
                    "SELECT count(*) FROM public.mds_unapproved_candidate_checkpoints", connection);
                var denied = await Assert.ThrowsAsync<PostgresException>(
                    async () => await read.ExecuteScalarAsync());
                Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denied.SqlState);
            }
        }
        Assert.Equal("UNAPPROVED", await StageAsync(owner, c, 1));
    }

    [Fact]
    public async Task ConflictingConcurrentWritersAreSerializedNotLastWriterWins()
    {
        var c = Candidate.Fresh();
        await using (var initial = Owner())
        {
            await initial.OpenAsync();
            Assert.Equal("UNAPPROVED", await StageAsync(initial, c, 1));
        }
        async Task<bool> TryStageAsync(long candidate)
        {
            await using var connection = Owner();
            await connection.OpenAsync();
            try
            {
                return await StageAsync(connection, c, candidate) == "UNAPPROVED";
            }
            catch (PostgresException ex) when (
                ex.SqlState is PostgresErrorCodes.CheckViolation or
                    PostgresErrorCodes.SerializationFailure or
                    PostgresErrorCodes.DeadlockDetected)
            {
                return false; // Failed closed, never silently accepted.
            }
        }
        // Independent connections compete on the same issuer/kind key.
        // Regardless of arrival order, a serial once raised must not fall.
        var results = await Task.WhenAll(Enumerable.Range(2, 8)
            .Select(i => TryStageAsync(i)));
        Assert.Contains(true, results);
        // Concurrent callers may be fail-closed due to deadlock/serialization;
        // the highest *accepted* serial must still be the final committed
        // high-water mark, rather than assuming all eight submissions commit.
        var highestAccepted = results
            .Select((accepted, index) => (accepted, serial: (long)index + 2))
            .Where(item => item.accepted)
            .Max(item => item.serial);
        await using var db = Owner();
        await db.OpenAsync();
        var actual = (await CurrentAsync(db, c)).Version;
        Assert.Equal(highestAccepted, actual);
        Assert.InRange(actual, 2L, 9L);
        Assert.InRange(await HistoryAsync(db, c), 2L, 9L);
        await Assert.ThrowsAsync<PostgresException>(() => StageAsync(db, c, actual - 1));
    }

    [Fact]
    public async Task SameSerialDifferentDigestsFromConcurrentConnectionsCannotBothCommit()
    {
        var c = Candidate.Fresh("ISSUER_CRL");
        await using (var initial = Owner())
        {
            await initial.OpenAsync();
            Assert.Equal("UNAPPROVED", await StageAsync(initial, c, 1));
        }
        async Task<bool> TryStageAsync(string digest)
        {
            await using var db = Owner();
            await db.OpenAsync();
            try
            {
                return await StageAsync(db, c, 2, digest: digest) == "UNAPPROVED";
            }
            catch (PostgresException ex) when (
                ex.SqlState is PostgresErrorCodes.CheckViolation or
                    PostgresErrorCodes.SerializationFailure)
            {
                return false;
            }
        }
        var results = await Task.WhenAll(
            TryStageAsync(Hash("first conflicting signed evidence")),
            TryStageAsync(Hash("different conflicting signed evidence")));
        Assert.Single(results, passed => passed);
        await using var verify = Owner();
        await verify.OpenAsync();
        Assert.Equal(2L, (await CurrentAsync(verify, c)).Version);
        Assert.Equal(2L, await HistoryAsync(verify, c));
    }
}
