using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib;

namespace TemporalMark.Infrastructure.WebAuthn;

/// <summary>
/// Non-authorizing inspection of UNTRUSTED, caller-supplied FIDO metadata.
/// A passing inspection is not a trusted MDS BLOB, verified manufacturer
/// attestation, registered WebAuthn credential or SQL approval. See ADR 0028.
/// </summary>
public sealed record ReviewerMdsMetadataPolicyObservation(
    string ReviewStatus, Guid AuthenticatorAaguid, int MetadataSerial,
    string PolicyStage);

/// <summary>
/// Conservative inspection-only gate for already parsed Fido2 4.3.3 models.
/// There is intentionally NO API/CLI/DB integration and NO positive trust bit:
/// production must first validate the BLOB's JWS/x5c, pinned R46 root and
/// revocation, persist monotonic signed snapshots and verify device CA path.
/// The objects passed here may be forged or stale, so results are UNAPPROVED.
/// </summary>
public static class ReviewerMdsMetadataPolicyPreflight
{
    private const int MaximumEntries = 100000;
    private const int MaximumStatuses = 32;
    private const int MaximumRoots = 8;
    private const int MaximumEncodedCertificateLength = 16000;

    public static ReviewerMdsMetadataPolicyObservation Inspect(
        ReviewerAttestationReviewCandidate? candidate,
        MetadataBLOBPayload? untrustedMetadata,
        int minimumPreviouslyObservedSerial,
        DateTimeOffset snapshotObservedUtc,
        DateTimeOffset nowUtc)
    {
        if (candidate is null ||
            candidate.ReviewStatus != "UNAPPROVED" ||
            candidate.AttestationType != "attca" ||
            candidate.AttestationFormat != "packed" ||
            candidate.AuthenticatorAaguid == Guid.Empty ||
            candidate.IsBackupEligible || candidate.IsBackedUp ||
            !IsUpperSha256(candidate.CredentialIdSha256) ||
            !IsUpperSha256(candidate.PublicKeySha256) ||
            untrustedMetadata is null ||
            untrustedMetadata.Number <= 0 ||
            minimumPreviouslyObservedSerial < 0 ||
            untrustedMetadata.Number < minimumPreviouslyObservedSerial ||
            untrustedMetadata.Entries is not { Length: >= 1 and <= MaximumEntries } ||
            nowUtc.Offset != TimeSpan.Zero ||
            snapshotObservedUtc.Offset != TimeSpan.Zero ||
            snapshotObservedUtc > nowUtc ||
            snapshotObservedUtc <= nowUtc.AddHours(-24))
        {
            throw Denied();
        }

        // nextUpdate is still a string in Fido2 4.3.3, but MDS 3.1.1
        // discourages relying on it alone and plans to remove it. Omission
        // does not bypass the separate 24-hour observation-time limit.
        if (!string.IsNullOrWhiteSpace(untrustedMetadata.NextUpdate))
        {
            if (!DateOnly.TryParseExact(untrustedMetadata.NextUpdate,
                    "yyyy-MM-dd", CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var nextUpdate) ||
                nextUpdate < DateOnly.FromDateTime(nowUtc.UtcDateTime))
                throw Denied();
        }

        // AAGUID MUST match exactly one entry. No fallback to a caller-
        // provided attestation certificate or a string-based trust root.
        MetadataBLOBPayloadEntry? relevantEntry = null;
        foreach (var entry in untrustedMetadata.Entries)
        {
            if (entry?.AaGuid != candidate.AuthenticatorAaguid)
                continue;
            if (relevantEntry is not null)
                throw Denied(); // duplicate / conflicting metadata model
            relevantEntry = entry;
        }

        var statement = relevantEntry?.MetadataStatement;
        if (statement is null ||
            statement.AaGuid != candidate.AuthenticatorAaguid ||
            statement.ProtocolFamily != "fido2" ||
            statement.Schema != 3 ||
            statement.AttestationTypes is not { Length: >= 1 and <= 16 } ||
            !statement.AttestationTypes.Contains("basic_full", StringComparer.Ordinal) ||
            statement.AttestationRootCertificates is not { Length: >= 1 and <= MaximumRoots } ||
            !string.IsNullOrEmpty(relevantEntry!.RogueListURL) ||
            !string.IsNullOrEmpty(relevantEntry.RogueListHash) ||
            relevantEntry.StatusReports is not { Length: >= 1 and <= MaximumStatuses } ||
            relevantEntry.StatusReports.Any(report => report is null ||
                !PermittedStatus(report.Status)))
            throw Denied();

        // Validate certificate *encoding only* (size/DER), NOT its chain,
        // CRL, AAGUID provenance, owner approval or signer trust. MDS permits
        // an intermediate or leaf as an attestation trust anchor, so do not
        // mistakenly assume every anchor must be a CA certificate.
        foreach (var root in statement.AttestationRootCertificates)
        {
            if (string.IsNullOrWhiteSpace(root) ||
                root.Length > MaximumEncodedCertificateLength)
                throw Denied();
            try
            {
                var der = Convert.FromBase64String(root);
                if (der.Length is < 128 or > 12000)
                    throw Denied();
                using var parsed = X509CertificateLoader.LoadCertificate(der);
                if (parsed.Version != 3)
                    throw Denied();
            }
            catch (Exception error) when (error is FormatException or CryptographicException or ArgumentException)
            {
                throw Denied();
            }
        }

        return new ReviewerMdsMetadataPolicyObservation(
            "UNAPPROVED", candidate.AuthenticatorAaguid,
            untrustedMetadata.Number, "MDS_METADATA_INSPECTION_ONLY");
    }

    private static bool PermittedStatus(AuthenticatorStatus status) =>
        status is AuthenticatorStatus.FIDO_CERTIFIED_L2 or
            AuthenticatorStatus.FIDO_CERTIFIED_L2plus or
            AuthenticatorStatus.FIDO_CERTIFIED_L3 or
            AuthenticatorStatus.FIDO_CERTIFIED_L3plus;

    private static bool IsUpperSha256(string? hash) =>
        hash is { Length: 64 } &&
        hash.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static UnauthorizedAccessException Denied() =>
        new("Untrusted, stale, revoked or nonconforming FIDO MDS policy metadata.");
}
