using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace TemporalMark.Infrastructure.WebAuthn;

/// <summary>
/// Test-only second, independently signed digest-of-witness check.
/// A caller-supplied "latest" seal SHA and public-key pin do NOT constitute
/// independent immutable custody, approved FIDO source or authorization.
/// </summary>
public sealed record ReviewerMdsSealedHighWaterCandidate(
    string ReviewStatus, string PolicyStage, string WitnessSha256,
    string SealSha256, int MatchedCandidates);

/// <summary>
/// Offline, non-authorizing layered witness check (ADR 0034 / #65).
/// Verifies two different RSA-PSS signature domains: a detached external
/// high-water seal that binds a witness hash, and the witness's original
/// signature via the existing ADR 0033 PostgreSQL read-only reconciler.
/// No production root/anchor, HSM, external append-only log, SQL grant,
/// database mutation, timestamp authority or credential enrollment.
/// </summary>
public static class ReviewerMdsOfflineSealedHighWaterCandidateVerifier
{
    private const string SealDomain =
        "TEMPORALMARK-UNAPPROVED-EXTERNAL-WITNESS-SEAL-1";
    private const int MaximumSealBytes = 4096;
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromHours(24);
    private static readonly TimeSpan MinimumLifetime = TimeSpan.FromSeconds(60);

    public static async Task<ReviewerMdsSealedHighWaterCandidate> ReconcileAsync(
        NpgsqlConnection? ownerConnection,
        byte[]? untrustedSignedWitness,
        byte[]? witnessSignature,
        RSA? callerSelectedWitnessTestKey,
        byte[]? sealedHighWater,
        byte[]? detachedSealSignature,
        RSA? callerSelectedSealAuthorityTestKey,
        string? independentlyExpectedTestAuthoritySpkiSha256,
        string? independentlyExpectedLatestSealSha256,
        DateTimeOffset nowUtc,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (ownerConnection is null || untrustedSignedWitness is null ||
            witnessSignature is null || callerSelectedWitnessTestKey is null ||
            sealedHighWater is not { Length: >= 180 and <= MaximumSealBytes } ||
            detachedSealSignature is null || callerSelectedSealAuthorityTestKey is null ||
            !IsSha256(independentlyExpectedTestAuthoritySpkiSha256) ||
            !IsSha256(independentlyExpectedLatestSealSha256) ||
            nowUtc.Offset != TimeSpan.Zero)
            throw Denied();

        try
        {
            if (callerSelectedSealAuthorityTestKey.KeySize is < 2048 or > 4096 ||
                detachedSealSignature.Length != callerSelectedSealAuthorityTestKey.KeySize / 8)
                throw Denied();

            // An external latest-seal digest and independent SPKI pin are
            // REQUIRED. In tests both are retained outside PostgreSQL;
            // security depends on custody which this code does not supply.
            var actualSpkiHash = SHA256.HashData(
                callerSelectedSealAuthorityTestKey.ExportSubjectPublicKeyInfo());
            var expectedSpkiHash =
                Convert.FromHexString(independentlyExpectedTestAuthoritySpkiSha256);
            if (!CryptographicOperations.FixedTimeEquals(
                actualSpkiHash, expectedSpkiHash))
                throw Denied();

            var sealSha = SHA256.HashData(sealedHighWater);
            var expectedSealSha =
                Convert.FromHexString(independentlyExpectedLatestSealSha256);
            if (!CryptographicOperations.FixedTimeEquals(sealSha, expectedSealSha))
                throw Denied();

            if (!callerSelectedSealAuthorityTestKey.VerifyData(
                sealedHighWater, detachedSealSignature,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
                throw Denied();

            // Do not normalize, trim, reserialize, HTML-decode or treat an
            // opaque caller-supplied unsigned value as a signed latest seal.
            foreach (var b in sealedHighWater)
                if (b != 10 && (b < 33 || b > 126))
                    throw Denied();
            if (sealedHighWater[^1] != (byte)'\n')
                throw Denied();

            var fields = Encoding.ASCII.GetString(sealedHighWater).Split('\n');
            if (fields.Length != 6 || fields[^1] != "" ||
                fields[0] != SealDomain ||
                !IsSha256(fields[1]) || !IsSha256(fields[2]) ||
                !CanonicalPositiveLong(fields[3], out var issuedSeconds) ||
                !CanonicalPositiveLong(fields[4], out var expiresSeconds))
                throw Denied();

            DateTimeOffset issuedUtc, expiresUtc;
            try
            {
                issuedUtc = DateTimeOffset.FromUnixTimeSeconds(issuedSeconds);
                expiresUtc = DateTimeOffset.FromUnixTimeSeconds(expiresSeconds);
            }
            catch (ArgumentOutOfRangeException)
            {
                throw Denied();
            }

            if (issuedUtc > nowUtc || expiresUtc <= nowUtc ||
                expiresUtc - issuedUtc < MinimumLifetime ||
                expiresUtc - issuedUtc > MaximumLifetime)
                throw Denied();

            if (!CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(untrustedSignedWitness),
                Convert.FromHexString(fields[2])))
                throw Denied();

            // Bind seal scope to the witness scope, not to an unrelated
            // partition of claimed FIDO MDS/CRL metadata.
            var witnessLines =
                Encoding.ASCII.GetString(untrustedSignedWitness).Split('\n');
            if (witnessLines.Length < 3 || witnessLines[1] != fields[1])
                throw Denied();

            // The existing ADR 0033 component then verifies the ORIGINAL
            // signed witness bytes and the FULL source-policy partition
            // under READ ONLY / REPEATABLE READ with physical-owner checks.
            var observation =
                await ReviewerMdsOfflineSignedCheckpointWitnessReconciler.ReconcileAsync(
                    ownerConnection, untrustedSignedWitness, witnessSignature,
                    callerSelectedWitnessTestKey, nowUtc, cancellationToken);

            if (observation.ReviewStatus != "UNAPPROVED" ||
                observation.PolicyStage !=
                    "SIGNED_WITNESS_ONLY_EXTERNAL_CUSTODY_UNPROVEN")
                throw Denied();

            return new ReviewerMdsSealedHighWaterCandidate(
                "UNAPPROVED", "TEST_HIGH_WATER_SEAL_EXTERNAL_CUSTODY_UNPROVEN",
                observation.WitnessSha256, Convert.ToHexString(sealSha),
                observation.MatchedCandidates);
        }
        catch (Exception error) when (error is not OperationCanceledException
                                      and not OutOfMemoryException)
        {
            // Intentionally avoid leaking raw signatures, witness contents,
            // database identity or proof of claimed manufacturer provenance.
            throw Denied();
        }
    }

    private static bool CanonicalPositiveLong(string raw, out long value) =>
        long.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture,
            out value) && value > 0 &&
        string.Equals(raw, value.ToString(CultureInfo.InvariantCulture),
            StringComparison.Ordinal);

    private static bool IsSha256(string? raw) =>
        raw is { Length: 64 } &&
        raw.All(c => c is (>= '0' and <= '9') or (>= 'A' and <= 'F'));

    private static UnauthorizedAccessException Denied() =>
        new("Unapproved high-water witness, signature, pin or checkpoint mismatch.");
}
