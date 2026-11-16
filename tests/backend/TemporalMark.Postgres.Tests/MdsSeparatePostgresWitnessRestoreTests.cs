using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// RED-first real TWO-PROCESS PostgreSQL witness smoke, hosted by a CI-only
/// second postgres:17.6 Docker profile. No production immutable witness,
/// approved FIDO manufacturer certificate or reviewer authorization.
/// </summary>
public sealed class MdsSeparatePostgresWitnessRestoreTests
{
    private static string Required(string name) =>
        Environment.GetEnvironmentVariable(name) ??
        throw new InvalidOperationException($"Missing required CI fixture {name}");

    private static string Hash(string input) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(input)));

    [Fact]
    public async Task SeparateReadonlyWitnessRetainsLatestAfterCompleteMainDatabaseRestore()
    {
        if (Environment.GetEnvironmentVariable("TEMPORALMARK_RUN_ISOLATED_WITNESS_TEST") != "1")
            return;

        var policy = Required("TEMPORALMARK_RESTORE_POLICY_SHA256");
        var issuer = Required("TEMPORALMARK_RESTORE_ISSUER_SHA256");
        var oldDigest = Required("TEMPORALMARK_RESTORE_OLD_EVIDENCE_SHA256");
        var latestDigest = Required("TEMPORALMARK_RESTORE_NEW_EVIDENCE_SHA256");

        await using var primary = new NpgsqlConnection(Required("TEMPORALMARK_TEST_DB"));
        await using var restored = new NpgsqlConnection(Required("TEMPORALMARK_RESTORE_TEST_DB"));
        await using var witnessOwner = new NpgsqlConnection(
            Required("TEMPORALMARK_WITNESS_OWNER_TEST_DB"));
        await using var witnessReader = new NpgsqlConnection(
            Required("TEMPORALMARK_WITNESS_TEST_DB"));
        await primary.OpenAsync();
        await restored.OpenAsync();
        await witnessOwner.OpenAsync();
        await witnessReader.OpenAsync();

        // Prove this is a physically separate PostgreSQL 17 cluster,
        // rather than merely two databases on the same PostgreSQL server.
        static async Task<string> ClusterId(NpgsqlConnection db)
        {
            await using var cmd = new NpgsqlCommand(
                "SELECT system_identifier FROM pg_control_system()", db);
            return Convert.ToString(await cmd.ExecuteScalarAsync(),
                       CultureInfo.InvariantCulture) ??
                   throw new InvalidOperationException("Missing PostgreSQL system id");
        }

        Assert.NotEqual(await ClusterId(primary), await ClusterId(witnessOwner));

        using var manifestSigner = RSA.Create(2048);
        using var sealSigner = RSA.Create(2048);
        var clock = DateTimeOffset.UtcNow.AddSeconds(3);
        var oldWitness = MdsFullPgDumpRestoreWitnessFixture.Witness(
            policy, issuer, 3, oldDigest, clock);
        var newWitness = MdsFullPgDumpRestoreWitnessFixture.Witness(
            policy, issuer, 4, latestDigest, clock);
        var oldSeal = MdsFullPgDumpRestoreWitnessFixture.Seal(policy, oldWitness, clock);
        var newSeal = MdsFullPgDumpRestoreWitnessFixture.Seal(policy, newWitness, clock);
        var oldSha = Convert.ToHexString(SHA256.HashData(oldSeal));
        var latestSha = Convert.ToHexString(SHA256.HashData(newSeal));
        var sealKeyPin = MdsFullPgDumpRestoreWitnessFixture.SpkiPin(sealSigner);
        var oldWitnessSig = MdsFullPgDumpRestoreWitnessFixture.Sign(
            manifestSigner, oldWitness);
        var newWitnessSig = MdsFullPgDumpRestoreWitnessFixture.Sign(
            manifestSigner, newWitness);
        var oldSealSig = MdsFullPgDumpRestoreWitnessFixture.Sign(sealSigner, oldSeal);
        var newSealSig = MdsFullPgDumpRestoreWitnessFixture.Sign(sealSigner, newSeal);

        static async Task<string> Stage(NpgsqlConnection owner, string policy,
            long serial, string sha)
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT public.record_unapproved_highwater_witness(@policy,@serial,@sha)
                """, owner);
            cmd.Parameters.AddWithValue("policy", policy);
            cmd.Parameters.AddWithValue("serial", serial);
            cmd.Parameters.AddWithValue("sha", sha);
            return (string)(await cmd.ExecuteScalarAsync() ??
                throw new InvalidOperationException("Witness write missing result"));
        }

        Assert.Equal("UNAPPROVED", await Stage(witnessOwner, policy, 3, oldSha));
        Assert.Equal("UNAPPROVED", await Stage(witnessOwner, policy, 4, latestSha));

        // Version monotonicity enforced atomically by PostgreSQL SQL,
        // independently of main TemporalMark V017 and its pg_restore.
        await Assert.ThrowsAsync<PostgresException>(() =>
            Stage(witnessOwner, policy, 3, oldSha));
        await Assert.ThrowsAsync<PostgresException>(() =>
            Stage(witnessOwner, policy, 4, Hash("same-version-different-seal")));
        await Assert.ThrowsAsync<PostgresException>(() =>
            Stage(witnessOwner, policy, 4, latestSha));
        await Assert.ThrowsAsync<PostgresException>(() =>
            Stage(witnessOwner, policy, 5, "not-a-sha256"));

        await using (var audit = new NpgsqlCommand("""
            SELECT (SELECT candidate_serial
                    FROM public.unapproved_witness_checkpoints
                    WHERE source_policy_sha256=@policy),
                   (SELECT count(*)
                    FROM public.unapproved_witness_events
                    WHERE source_policy_sha256=@policy)
            """, witnessOwner))
        {
            audit.Parameters.AddWithValue("policy", policy);
            await using var row = await audit.ExecuteReaderAsync();
            Assert.True(await row.ReadAsync());
            Assert.Equal(4L, row.GetInt64(0));
            Assert.Equal(2L, row.GetInt64(1));
            Assert.False(await row.ReadAsync());
        }

        // Reader is a different DB login on a separate PostgreSQL cluster.
        // It cannot call the witness writer or change the monotonic row.
        await using (var role = new NpgsqlCommand("""
            SELECT current_user, session_user,
                has_table_privilege(current_user,
                    'public.unapproved_witness_checkpoints','SELECT'),
                has_table_privilege(current_user,
                    'public.unapproved_witness_checkpoints','UPDATE'),
                has_table_privilege(current_user,
                    'public.unapproved_witness_checkpoints','DELETE'),
                has_table_privilege(current_user,
                    'public.unapproved_witness_events','SELECT'),
                has_function_privilege(current_user,
                    'public.record_unapproved_highwater_witness(text,bigint,text)',
                    'EXECUTE')
            """, witnessReader))
        await using (var row = await role.ExecuteReaderAsync())
        {
            Assert.True(await row.ReadAsync());
            Assert.Equal("temporalmark_witness_reader", row.GetString(0));
            Assert.Equal("temporalmark_witness_reader", row.GetString(1));
            Assert.True(row.GetBoolean(2));
            for (var i = 3; i <= 6; i++)
                Assert.False(row.GetBoolean(i));
            Assert.False(await row.ReadAsync());
        }

        await Assert.ThrowsAsync<PostgresException>(() =>
            Stage(witnessReader, policy, 5, Hash("reader-cannot-write")));

        Task<ReviewerMdsIsolatedPostgresWitnessCandidate> Check(
            NpgsqlConnection main, NpgsqlConnection external,
            byte[] witness, byte[] witnessSignature,
            byte[] seal, byte[] sealSignature, string pin) =>
            ReviewerMdsIsolatedPostgresWitnessReader.ReconcileAsync(
                main, external, witness, witnessSignature, manifestSigner,
                seal, sealSignature, sealSigner, pin, clock);

        var current = await Check(primary, witnessReader, newWitness,
            newWitnessSig, newSeal, newSealSig, sealKeyPin);
        Assert.Equal("UNAPPROVED", current.ReviewStatus);
        Assert.Equal("SEPARATE_TEST_POSTGRES_WITNESS_NO_IMMUTABLE_CUSTODY",
            current.PolicyStage);
        Assert.Equal(4L, current.LatestSerial);
        Assert.Equal(latestSha, current.SealSha256);
        Assert.Equal(1, current.MatchedCandidates);

        // A full logical restore of the main application DB to serial 3
        // does not roll back this SECOND PostgreSQL SERVER at serial 4.
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(restored, witnessReader, oldWitness, oldWitnessSig,
                oldSeal, oldSealSig, sealKeyPin));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(restored, witnessReader, newWitness, newWitnessSig,
                newSeal, newSealSig, sealKeyPin));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(primary, witnessReader, oldWitness, oldWitnessSig,
                oldSeal, oldSealSig, sealKeyPin));

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(primary, witnessOwner, newWitness, newWitnessSig,
                newSeal, newSealSig, sealKeyPin));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(primary, witnessReader, newWitness, newWitnessSig,
                newSeal, newSealSig, Hash("wrong-test-root")));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(primary, witnessReader, newWitness,
                MdsFullPgDumpRestoreWitnessFixture.Sign(sealSigner, newWitness),
                newSeal, newSealSig, sealKeyPin));

        // NO fallback to the old signed file or a caller-provided test
        // latest hash when the second PostgreSQL service is unavailable.
        await witnessReader.CloseAsync();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(primary, witnessReader, newWitness, newWitnessSig,
                newSeal, newSealSig, sealKeyPin));
    }
}
