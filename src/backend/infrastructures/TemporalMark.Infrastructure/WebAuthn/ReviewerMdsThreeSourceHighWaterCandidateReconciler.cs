using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace TemporalMark.Infrastructure.WebAuthn;

/// <summary>
/// TEST-ONLY: three mutually consistent UNAPPROVED observations are not
/// independent custody, verified FIDO authority, a trusted signer or a
/// production authorization. See ADR 0041 / #72.
/// </summary>
public sealed record ReviewerMdsThreeSourceHighWaterCandidate(
    string ReviewStatus, string PolicyStage, long LatestSerial,
    string SealSha256, int MatchedCandidates);

/// <summary>
/// Isolated non-authorizing composition of a signed local test file journal,
/// an independent CI PostgreSQL witness and original V017 primary DB.
/// The file is not WORM or outside the disposable CI host's control.
/// No API, registrar, enrollment, decision or production call site exists.
/// </summary>
public static class ReviewerMdsThreeSourceHighWaterCandidateReconciler
{
    private const string JournalStage =
        "TEST_FILE_HIGH_WATER_NO_INDEPENDENT_CUSTODY";
    private const string PostgresStage =
        "SEPARATE_TEST_POSTGRES_WITNESS_NO_IMMUTABLE_CUSTODY";
    private const string ResultStage =
        "THREE_TEST_STORES_NO_INDEPENDENT_CUSTODY";

    public static async Task<ReviewerMdsThreeSourceHighWaterCandidate>
        ReconcileAsync(
            NpgsqlConnection? primaryOwner,
            NpgsqlConnection? separateWitnessReader,
            string? testJournalPath,
            string? sourcePolicySha256,
            string? callerSelectedJournalSpkiPin,
            RSA? callerSelectedJournalTestPublicKey,
            byte[]? originalManifest,
            byte[]? manifestSignature,
            RSA? callerSelectedManifestTestKey,
            byte[]? originalSeal,
            byte[]? sealSignature,
            RSA? callerSelectedSealTestKey,
            string? callerSelectedSealSpkiPin,
            DateTimeOffset nowUtc,
            CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (originalManifest is null || sourcePolicySha256 is null ||
            !SameClaimedPolicy(originalManifest, sourcePolicySha256))
            throw Denied();

        try
        {
            // First check the complete ORIGINAL signed journal before
            // inspecting either SQL database. No automatic bootstrap,
            // substitute digest, or fallback to the older database.
            var before = ReviewerMdsOfflineFileHighWaterJournal.InspectLatest(
                testJournalPath, sourcePolicySha256,
                callerSelectedJournalSpkiPin,
                callerSelectedJournalTestPublicKey, nowUtc);
            if (before.ReviewStatus != "UNAPPROVED" ||
                before.PolicyStage != JournalStage ||
                before.CandidateSerial <= 0 ||
                !ValidSha(before.SealSha256) ||
                !ValidSha(before.PayloadSha256))
                throw Denied();

            cancellationToken.ThrowIfCancellationRequested();
            // This separate PostgreSQL reader must independently validate
            // restricted CI reader roles, newest seal, *original signed*
            // manifest/seal and exact READ ONLY V017 primary snapshot.
            var verified = await ReviewerMdsIsolatedPostgresWitnessReader
                .ReconcileAsync(
                    primaryOwner, separateWitnessReader, originalManifest,
                    manifestSignature, callerSelectedManifestTestKey,
                    originalSeal, sealSignature, callerSelectedSealTestKey,
                    callerSelectedSealSpkiPin, nowUtc, cancellationToken);

            if (verified.ReviewStatus != "UNAPPROVED" ||
                verified.PolicyStage != PostgresStage ||
                verified.LatestSerial != before.CandidateSerial ||
                verified.MatchedCandidates <= 0 ||
                !SameSha(verified.SealSha256, before.SealSha256))
                throw Denied();

            cancellationToken.ThrowIfCancellationRequested();
            // This catches ordinary concurrent journal advances during
            // SQL checking. Still NOT atomic across filesystem/DB and not
            // protected against a privileged three-store replay.
            var after = ReviewerMdsOfflineFileHighWaterJournal.InspectLatest(
                testJournalPath, sourcePolicySha256,
                callerSelectedJournalSpkiPin,
                callerSelectedJournalTestPublicKey, nowUtc);
            if (after.ReviewStatus != "UNAPPROVED" ||
                after.PolicyStage != JournalStage ||
                after.CandidateSerial != before.CandidateSerial ||
                !SameSha(after.SealSha256, before.SealSha256) ||
                !SameSha(after.PayloadSha256, before.PayloadSha256))
                throw Denied();

            return new ReviewerMdsThreeSourceHighWaterCandidate(
                "UNAPPROVED", ResultStage, verified.LatestSerial,
                verified.SealSha256, verified.MatchedCandidates);
        }
        catch (Exception error) when (error is not OperationCanceledException
                                      and not OutOfMemoryException)
        {
            // Fail closed on SQL outage, unreadable/missing/corrupt journal,
            // invalid pins, wrong source, stale versions or mismatched seal.
            throw Denied();
        }
    }

    // Scope is parsed only to bind the journal lookup to the exact policy
    // claim in the incoming manifest. The existing signer verifier later
    // authenticates the ORIGINAL bytes, not these untrusted parsed fields.
    private static bool SameClaimedPolicy(byte[] manifest, string policy)
    {
        if (manifest.Length is < 128 or > 65536 || !ValidSha(policy))
            return false;
        var fields = Encoding.ASCII.GetString(manifest).Split('\n');
        return fields.Length == 7 &&
               string.Equals(fields[1], policy, StringComparison.Ordinal);
    }

    private static bool ValidSha(string? value) =>
        value is { Length: 64 } &&
        value.All(c => c is (>= 'A' and <= 'F') or (>= '0' and <= '9'));

    private static bool SameSha(string? left, string? right) =>
        ValidSha(left) && ValidSha(right) &&
        CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(left!), Convert.FromHexString(right!));

    private static UnauthorizedAccessException Denied() =>
        new("Unapproved or inconsistent three-source test high-water evidence.");
}
