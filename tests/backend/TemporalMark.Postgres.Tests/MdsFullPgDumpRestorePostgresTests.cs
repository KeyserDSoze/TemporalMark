using System.Security.Cryptography;
using Npgsql;
using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// RED-first logical-full-database pg_dump/pg_restore integration contract.
/// The shell runner creates a separately restored database from an OLD
/// archive, whereas the live original database already has a NEW candidate.
/// Test keys/pins live solely in this test process, not in either database.
/// The successful result is NEVER FIDO/CRL trust or authorization.
/// </summary>
public sealed class MdsFullPgDumpRestorePostgresTests
{
    [Fact]
    public async Task EntireLogicalDatabaseRestoreRejectsOldSignedWitnessWithRetainedNewSealPin()
    {
        // The separate mandatory CI step supplies two databases after an
        // actual pg_dump -Fc / pg_restore; ordinary unit-test runs do not
        // create databases or depend on a Docker CLI.
        if (Environment.GetEnvironmentVariable("TEMPORALMARK_RUN_FULL_PGDUMP_RESTORE_TEST") != "1")
            return;

        static string Required(string key) =>
            Environment.GetEnvironmentVariable(key) ??
            throw new InvalidOperationException($"Missing required test fixture {key}");

        var policy = Required("TEMPORALMARK_RESTORE_POLICY_SHA256");
        var issuer = Required("TEMPORALMARK_RESTORE_ISSUER_SHA256");
        var oldDigest = Required("TEMPORALMARK_RESTORE_OLD_EVIDENCE_SHA256");
        var latestDigest = Required("TEMPORALMARK_RESTORE_NEW_EVIDENCE_SHA256");

        await using var live = new NpgsqlConnection(Required("TEMPORALMARK_TEST_DB"));
        await using var restored = new NpgsqlConnection(Required("TEMPORALMARK_RESTORE_TEST_DB"));
        await live.OpenAsync();
        await restored.OpenAsync();

        static async Task<(long Serial, string Digest)> ReadCandidate(
            NpgsqlConnection db, string policy, string issuer)
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT candidate_serial, signed_evidence_sha256
                FROM public.mds_unapproved_candidate_checkpoints
                WHERE source_policy_sha256=@policy
                  AND candidate_kind='MDS_BLOB'
                  AND issuer_key_sha256=@issuer
                """, db);
            cmd.Parameters.AddWithValue("policy", policy);
            cmd.Parameters.AddWithValue("issuer", issuer);
            await using var reader = await cmd.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            var result = (reader.GetInt64(0), reader.GetString(1));
            Assert.False(await reader.ReadAsync());
            return result;
        }

        var old = await ReadCandidate(restored, policy, issuer);
        var newest = await ReadCandidate(live, policy, issuer);
        Assert.Equal(3L, old.Serial);
        Assert.Equal(oldDigest, old.Digest);
        Assert.Equal(4L, newest.Serial);
        Assert.Equal(latestDigest, newest.Digest);

        // pg_restore must preserve the FULL 17-migration schema and SQL
        // security posture. --no-acl would incorrectly revive PUBLIC
        // function permissions; the integration runner MUST NOT pass it.
        await using (var integrity = new NpgsqlCommand("""
            SELECT
              (SELECT count(*) FROM public.schema_migrations),
              has_function_privilege('temporalmark_runtime_group',
                'public.record_unapproved_mds_checkpoint_candidate(text,text,bigint,text,text,integer,text)',
                'EXECUTE'),
              has_function_privilege('temporalmark_approver_group',
                'public.record_unapproved_mds_checkpoint_candidate(text,text,bigint,text,text,integer,text)',
                'EXECUTE'),
              has_function_privilege('temporalmark_provisioner_group',
                'public.record_unapproved_mds_checkpoint_candidate(text,text,bigint,text,text,integer,text)',
                'EXECUTE'),
              has_function_privilege('temporalmark_credential_registrar_group',
                'public.record_unapproved_mds_checkpoint_candidate(text,text,bigint,text,text,integer,text)',
                'EXECUTE'),
              has_table_privilege('temporalmark_runtime_group',
                'public.mds_unapproved_candidate_checkpoints','SELECT'),
              has_table_privilege('temporalmark_approver_group',
                'public.mds_unapproved_candidate_events','INSERT')
            """, restored))
        await using (var row = await integrity.ExecuteReaderAsync())
        {
            Assert.True(await row.ReadAsync());
            Assert.Equal(17L, row.GetInt64(0));
            for (var i = 1; i <= 6; i++)
                Assert.False(row.GetBoolean(i));
            Assert.False(await row.ReadAsync());
        }

        using var witnessKey = RSA.Create(2048);
        using var separateSealKey = RSA.Create(2048);
        var now = DateTimeOffset.UtcNow;
        var oldWitness = MdsFullPgDumpRestoreWitnessFixture.Witness(
            policy, issuer, 3, oldDigest, now);
        var newWitness = MdsFullPgDumpRestoreWitnessFixture.Witness(
            policy, issuer, 4, latestDigest, now);
        var oldSeal = MdsFullPgDumpRestoreWitnessFixture.Seal(policy, oldWitness, now);
        var newSeal = MdsFullPgDumpRestoreWitnessFixture.Seal(policy, newWitness, now);
        var latestSealPin = Convert.ToHexString(SHA256.HashData(newSeal));
        var oldSealPin = Convert.ToHexString(SHA256.HashData(oldSeal));
        var authorityPin = MdsFullPgDumpRestoreWitnessFixture.SpkiPin(separateSealKey);
        var oldWitnessSignature = MdsFullPgDumpRestoreWitnessFixture.Sign(witnessKey, oldWitness);
        var newWitnessSignature = MdsFullPgDumpRestoreWitnessFixture.Sign(witnessKey, newWitness);
        var oldSealSignature = MdsFullPgDumpRestoreWitnessFixture.Sign(separateSealKey, oldSeal);
        var newSealSignature = MdsFullPgDumpRestoreWitnessFixture.Sign(separateSealKey, newSeal);

        // The high-water evidence now survives an open/close/reopen of an
        // actual separate on-disk file, not a variable inside either
        // PostgreSQL database. The test file remains mutable by host admins,
        // so this is STILL NOT an independently custodied WORM authority.
        using (var journalKey = RSA.Create(2048))
        {
            var journalPath = Path.Combine(Path.GetTempPath(),
                "temporalmark-unapproved-journal-" + Guid.NewGuid().ToString("N"));
            var journalPin = MdsFullPgDumpRestoreWitnessFixture.SpkiPin(journalKey);
            try
            {
                ReviewerMdsOfflineFileHighWaterJournal.BootstrapNewForTests(
                    journalPath, policy, journalPin);

                var original = MdsFullPgDumpRestoreWitnessFixture.JournalEvent(
                    policy, 3, oldSealPin, new string('0', 64), now.AddSeconds(-2));
                var first = ReviewerMdsOfflineFileHighWaterJournal.AppendSignedForTests(
                    journalPath, policy, journalPin, journalKey, original,
                    MdsFullPgDumpRestoreWitnessFixture.Sign(journalKey, original), now);
                var olderFile = File.ReadAllBytes(journalPath);

                var next = MdsFullPgDumpRestoreWitnessFixture.JournalEvent(
                    policy, 4, latestSealPin, first.PayloadSha256, now.AddSeconds(-1));
                ReviewerMdsOfflineFileHighWaterJournal.AppendSignedForTests(
                    journalPath, policy, journalPin, journalKey, next,
                    MdsFullPgDumpRestoreWitnessFixture.Sign(journalKey, next), now);

                var observedAfterRestore =
                    ReviewerMdsOfflineFileHighWaterJournal.InspectLatest(
                        journalPath, policy, journalPin, journalKey, now);
                Assert.Equal("UNAPPROVED", observedAfterRestore.ReviewStatus);
                Assert.Equal(4L, observedAfterRestore.CandidateSerial);
                Assert.Equal(latestSealPin, observedAfterRestore.SealSha256);

                // The external on-disk high-water SHA (not a caller-chosen
                // old one) rejects even a CORRECTLY signed past witness
                // against the fully logically restored serial 3 database.
                await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                    ReviewerMdsOfflineSealedHighWaterCandidateVerifier.ReconcileAsync(
                        restored, oldWitness, oldWitnessSignature, witnessKey,
                        oldSeal, oldSealSignature, separateSealKey,
                        authorityPin, observedAfterRestore.SealSha256, now));

                // Deliberate residual attack: the same host administrator
                // can restore an older file journal ALONG WITH the DB.
                // This positive result is STILL UNAPPROVED, not trusted.
                File.WriteAllBytes(journalPath, olderFile);
                var replayedJournal = ReviewerMdsOfflineFileHighWaterJournal.InspectLatest(
                    journalPath, policy, journalPin, journalKey, now);
                Assert.Equal(3L, replayedJournal.CandidateSerial);
                Assert.Equal(oldSealPin, replayedJournal.SealSha256);
            }
            finally
            {
                if (File.Exists(journalPath))
                    File.Delete(journalPath);
            }
        }

        Task<ReviewerMdsSealedHighWaterCandidate> Reconcile(
            NpgsqlConnection db, byte[] witness, byte[] witnessSignature,
            byte[] seal, byte[] sealSignature, string expectedLatestSealPin) =>
            ReviewerMdsOfflineSealedHighWaterCandidateVerifier.ReconcileAsync(
                db, witness, witnessSignature, witnessKey,
                seal, sealSignature, separateSealKey,
                authorityPin, expectedLatestSealPin, now);

        Assert.Equal("UNAPPROVED",
            (await Reconcile(live, newWitness, newWitnessSignature,
                newSeal, newSealSignature, latestSealPin)).ReviewStatus);

        // The OLDER FULL LOGICAL restored database must not fit the newest
        // signed manifest, even though both signatures and pins are valid.
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Reconcile(restored, newWitness, newWitnessSignature,
                newSeal, newSealSignature, latestSealPin));

        // This earlier signed pair was genuinely valid before pg_dump:
        // retaining the newer seal hash OUTSIDE the restored DB detects it.
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Reconcile(restored, oldWitness, oldWitnessSignature,
                oldSeal, oldSealSignature, latestSealPin));

        // Critical gap of #64, deliberately exposed rather than hidden:
        // if the caller substitutes the old 'latest' pin too, replay of
        // restored DB + old signed witness/seal is indistinguishable.
        var replay = await Reconcile(restored, oldWitness, oldWitnessSignature,
            oldSeal, oldSealSignature, oldSealPin);
        Assert.Equal("UNAPPROVED", replay.ReviewStatus);
        Assert.Equal("TEST_HIGH_WATER_SEAL_EXTERNAL_CUSTODY_UNPROVEN", replay.PolicyStage);

        // Equivocation at the SAME old serial must fail even when its old
        // seal was valid; this is owner-only tampering on the test database.
        await using (var mutate = new NpgsqlCommand("""
            UPDATE public.mds_unapproved_candidate_checkpoints
            SET signed_evidence_sha256=@digest
            WHERE source_policy_sha256=@policy
              AND candidate_kind='MDS_BLOB'
              AND issuer_key_sha256=@issuer
            """, restored))
        {
            mutate.Parameters.AddWithValue("digest",
                Convert.ToHexString(SHA256.HashData("tampered-logical-restore"u8)));
            mutate.Parameters.AddWithValue("policy", policy);
            mutate.Parameters.AddWithValue("issuer", issuer);
            Assert.Equal(1, await mutate.ExecuteNonQueryAsync());
        }
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Reconcile(restored, oldWitness, oldWitnessSignature,
                oldSeal, oldSealSignature, oldSealPin));
    }
}
