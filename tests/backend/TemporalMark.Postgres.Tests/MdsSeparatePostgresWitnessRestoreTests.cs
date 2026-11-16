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
[Collection("TemporalMarkFullLogicalRestoreSerial")]
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
        await using var witnessWriter = new NpgsqlConnection(
            Required("TEMPORALMARK_WITNESS_WRITER_TEST_DB"));
        await primary.OpenAsync();
        await restored.OpenAsync();
        await witnessOwner.OpenAsync();
        await witnessReader.OpenAsync();
        // RED FIRST: CI does not yet bootstrap this non-superuser writer.
        // The test must fail until the separate witness SQL grants exactly
        // function EXECUTE and no direct state/audit access.
        await witnessWriter.OpenAsync();

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

        Assert.Equal("UNAPPROVED", await Stage(witnessWriter, policy, 3, oldSha));
        Assert.Equal("UNAPPROVED", await Stage(witnessWriter, policy, 4, latestSha));

        // Version monotonicity enforced atomically by PostgreSQL SQL,
        // independently of main TemporalMark V017 and its pg_restore.
        await Assert.ThrowsAsync<PostgresException>(() =>
            Stage(witnessWriter, policy, 3, oldSha));
        await Assert.ThrowsAsync<PostgresException>(() =>
            Stage(witnessWriter, policy, 4, Hash("same-version-different-seal")));
        await Assert.ThrowsAsync<PostgresException>(() =>
            Stage(witnessWriter, policy, 4, latestSha));
        await Assert.ThrowsAsync<PostgresException>(() =>
            Stage(witnessWriter, policy, 5, "not-a-sha256"));

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

        // Writer is an ordinary login, NOT a member of the non-login
        // definer and NOT a witness server superuser. It can EXECUTE one
        // constrained function but cannot directly see/change any witness
        // row, event, sequence, function body or database schema.
        await using (var privilege = new NpgsqlCommand("""
            SELECT current_user, session_user,
                   r.rolsuper, r.rolcreaterole, r.rolcreatedb,
                   r.rolreplication, r.rolinherit,
                   has_function_privilege(current_user,
                       'public.record_unapproved_highwater_witness(text,bigint,text)',
                       'EXECUTE'),
                   has_database_privilege(current_user,
                       'temporalmark_witness', 'TEMPORARY'),
                   has_schema_privilege(current_user, 'public', 'CREATE'),
                   pg_has_role(current_user, 'temporalmark_witness_data_owner',
                       'MEMBER'),
                   has_sequence_privilege(current_user,
                       'public.unapproved_witness_events_event_id_seq', 'USAGE'),
                   (SELECT p.prosecdef FROM pg_catalog.pg_proc p
                    WHERE p.oid =
                    'public.record_unapproved_highwater_witness(text,bigint,text)'
                        ::pg_catalog.regprocedure),
                   (SELECT pg_catalog.pg_get_userbyid(c.relowner)
                    FROM pg_catalog.pg_class c
                    WHERE c.oid =
                       'public.unapproved_witness_checkpoints'::pg_catalog.regclass),
                   (SELECT pg_catalog.pg_get_userbyid(p.proowner)
                    FROM pg_catalog.pg_proc p
                    WHERE p.oid =
                    'public.record_unapproved_highwater_witness(text,bigint,text)'
                        ::pg_catalog.regprocedure)
            FROM pg_catalog.pg_roles r WHERE r.rolname=current_user
            """, witnessWriter))
        await using (var row = await privilege.ExecuteReaderAsync())
        {
            Assert.True(await row.ReadAsync());
            Assert.Equal("temporalmark_witness_writer", row.GetString(0));
            Assert.Equal("temporalmark_witness_writer", row.GetString(1));
            for (var i = 2; i <= 5; i++)
                Assert.False(row.GetBoolean(i));
            Assert.True(row.GetBoolean(7));
            foreach (var index in new[] { 8, 9, 10, 11 })
                Assert.False(row.GetBoolean(index));
            Assert.True(row.GetBoolean(12));
            Assert.Equal("temporalmark_witness_data_owner", row.GetString(13));
            Assert.Equal("temporalmark_witness_data_owner", row.GetString(14));
            Assert.False(await row.ReadAsync());
        }

        foreach (var relation in new[]
                 {
                     "public.unapproved_witness_checkpoints",
                     "public.unapproved_witness_events"
                 })
        {
            foreach (var operation in new[]
                     {
                         "SELECT", "INSERT", "UPDATE", "DELETE",
                         "TRUNCATE", "REFERENCES", "TRIGGER"
                     })
            {
                await using var grant = new NpgsqlCommand("""
                    SELECT has_table_privilege(current_user,@relation,@permission)
                    """, witnessWriter);
                grant.Parameters.AddWithValue("relation", relation);
                grant.Parameters.AddWithValue("permission", operation);
                Assert.False((bool)(await grant.ExecuteScalarAsync())!);
            }
        }

        foreach (var deniedSql in new[]
                 {
                     "SELECT count(*) FROM public.unapproved_witness_events",
                     "SELECT count(*) FROM public.unapproved_witness_checkpoints",
                     "DELETE FROM public.unapproved_witness_checkpoints",
                     "TRUNCATE TABLE public.unapproved_witness_events",
                     "UPDATE public.unapproved_witness_checkpoints SET candidate_serial=1",
                     "CREATE TEMP TABLE witness_bypass (serial bigint)",
                     "CREATE TABLE public.witness_bypass (serial bigint)",
                     "SET ROLE temporalmark_witness_data_owner"
                 })
        {
            await using var denied = new NpgsqlCommand(deniedSql, witnessWriter);
            await Assert.ThrowsAsync<PostgresException>(() =>
                denied.ExecuteNonQueryAsync());
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

        // Missing scope in the independent witness must fail CLOSED:
        // a caller cannot substitute an arbitrary latest SHA or fallback
        // to a forged local journal.
        var missingPolicy = Hash("unrecorded-witness-scope-" + Guid.NewGuid());
        var missingManifest = MdsFullPgDumpRestoreWitnessFixture.Witness(
            missingPolicy, issuer, 4, latestDigest, clock);
        var missingSeal = MdsFullPgDumpRestoreWitnessFixture.Seal(
            missingPolicy, missingManifest, clock);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(primary, witnessReader, missingManifest,
                MdsFullPgDumpRestoreWitnessFixture.Sign(
                    manifestSigner, missingManifest),
                missingSeal, MdsFullPgDumpRestoreWitnessFixture.Sign(
                    sealSigner, missingSeal), sealKeyPin));

        // Clock/retention violations on the external witness are denied,
        // even if its signed caller-side seal and primary state still match.
        async Task SetWitnessObservation(string intervalExpression)
        {
            // SQL clause is fixed by the test, never user-supplied or
            // interpolated from external command input.
            var sql = "UPDATE public.unapproved_witness_checkpoints " +
                "SET observed_utc = clock_timestamp() " + intervalExpression +
                " WHERE source_policy_sha256=@policy";
            await using var update = new NpgsqlCommand(sql, witnessOwner);
            update.Parameters.AddWithValue("policy", policy);
            Assert.Equal(1, await update.ExecuteNonQueryAsync());
        }

        await SetWitnessObservation("- interval '2 days'");
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(primary, witnessReader, newWitness, newWitnessSig,
                newSeal, newSealSig, sealKeyPin));
        await SetWitnessObservation("+ interval '1 day'");
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(primary, witnessReader, newWitness, newWitnessSig,
                newSeal, newSealSig, sealKeyPin));

        // NO fallback to the old signed file or a caller-provided test
        // latest hash when the second PostgreSQL service is unavailable.
        await witnessReader.CloseAsync();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Check(primary, witnessReader, newWitness, newWitnessSig,
                newSeal, newSealSig, sealKeyPin));
    }
}
