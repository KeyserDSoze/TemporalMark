using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TemporalMark.Infrastructure.WebAuthn;

/// <summary>
/// Non-authorizing proof of TWO independently issuer-signed DER CRLs against
/// a caller-supplied test root → intermediate CA → signer leaf path.
/// Even successful checks do NOT establish FIDO MDS trust, current global
/// revocation status, or approval to register or activate credentials.
/// </summary>
public sealed record ReviewerMdsTwoHopCrlCandidate(
    string ReviewStatus, string PolicyStage,
    string LeafCrlSha256, string IntermediateCrlSha256);

/// <summary>
/// Offline test-only candidate for exactly two non-root certificates:
/// signer leaf issued by intermediate, intermediate issued by test root.
/// Uses the SAME strict BC 2.7.0 v2 CRL verifier as the direct-issued case
/// (ADR 0030) and .NET custom-root X509 path checks. ADR 0031.
/// No production root, FIDO JWT, attestation or SQL authorization is wired.
/// </summary>
public static class ReviewerMdsOfflineTwoHopCrlCandidateVerifier
{
    public static ReviewerMdsTwoHopCrlCandidate Inspect(
        X509Certificate2? signerLeaf,
        X509Certificate2? untrustedIntermediateCa,
        X509Certificate2? untrustedTestRoot,
        byte[]? leafIssuerSignedDerCrl,
        byte[]? intermediateIssuerSignedDerCrl,
        DateTimeOffset nowUtc)
    {
        if (signerLeaf is null || untrustedIntermediateCa is null ||
            untrustedTestRoot is null ||
            nowUtc.Offset != TimeSpan.Zero ||
            leafIssuerSignedDerCrl is null ||
            intermediateIssuerSignedDerCrl is null)
            throw Denied();

        try
        {
            // Establish this EXACT cryptographic certificate path without
            // trusting arbitrary host CAs, fetching issuer URLs or silently
            // truncating to a direct one-hop check. NoCheck is used ONLY
            // to construct certificate signatures; BOTH actual CRLs below
            // are cryptographically checked separately.
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(untrustedTestRoot);
            chain.ChainPolicy.ExtraStore.Add(untrustedIntermediateCa);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationTime = nowUtc.UtcDateTime;

            if (!chain.Build(signerLeaf) ||
                chain.ChainElements.Count != 3 ||
                !CryptographicOperations.FixedTimeEquals(
                    chain.ChainElements[0].Certificate.RawData, signerLeaf.RawData) ||
                !CryptographicOperations.FixedTimeEquals(
                    chain.ChainElements[1].Certificate.RawData, untrustedIntermediateCa.RawData) ||
                !CryptographicOperations.FixedTimeEquals(
                    chain.ChainElements[2].Certificate.RawData, untrustedTestRoot.RawData))
                throw Denied();

            // The intermediate CA must be nonrevoked in a current CRL
            // signed by the root; the leaf must independently be nonrevoked
            // in a current CRL signed by the intermediate. Both checks use
            // issuer-key and subject-serial binding, v2 full-CRL signatures,
            // cRLSign/keyCertSign, validity and strict extension rules.
            var intermediateCrlHash =
                ReviewerMdsOfflineCrlCandidateVerifier.VerifySignedDirectCrl(
                    untrustedIntermediateCa, untrustedTestRoot,
                    intermediateIssuerSignedDerCrl, nowUtc, subjectIsCa: true);
            var leafCrlHash =
                ReviewerMdsOfflineCrlCandidateVerifier.VerifySignedDirectCrl(
                    signerLeaf, untrustedIntermediateCa,
                    leafIssuerSignedDerCrl, nowUtc, subjectIsCa: false);

            // Deliberately NO trusted root output, registered signer, raw
            // certificates or authority. Caller-selected root and CRLs are
            // insufficient for FIDO MDS production provenance or CAB review.
            return new ReviewerMdsTwoHopCrlCandidate(
                "UNAPPROVED", "TWO_HOP_CRL_ONLY_ROOT_UNTRUSTED",
                leafCrlHash, intermediateCrlHash);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            throw Denied();
        }
    }

    private static UnauthorizedAccessException Denied() =>
        new("Untrusted or revoked two-hop FIDO MDS X509 chain/CRL candidate.");
}
