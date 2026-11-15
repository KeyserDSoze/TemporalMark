using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace TemporalMark.Infrastructure.WebAuthn;

/// <summary>
/// NON-AUTHORIZING test-only CRL signature observation for a directly issued
/// leaf. The issuer/root itself is caller supplied and therefore UNTRUSTED.
/// Real FIDO MDS signer root, full path revocation, distribution-point policy,
/// and serial/CRL state persistence remain unresolved in #57.
/// </summary>
public sealed record ReviewerMdsCrlCryptographicCandidate(
    string ReviewStatus, string PolicyStage, string CrlSha256);

/// <summary>
/// Strict, offline DER X509 v2 CRL proof for ONE directly issued certificate,
/// not an MDS trust decision or an authorization interface. Uses the pinned
/// maintained BouncyCastle 2.7.0 for CRL parsing/signature/revocation checks.
/// No network, trust-store fallback, CRL URL or SQL credentials are available.
/// </summary>
public static class ReviewerMdsOfflineCrlCandidateVerifier
{
    private const int MaximumCrlBytes = 1_048_576;
    private const int MaximumRevokedEntries = 10000;
    private static readonly TimeSpan MaximumCrlPeriod = TimeSpan.FromDays(7);
    // SHA256WITHRSA only for this intentionally restrictive test slice.
    private const string SupportedSignatureOid = "1.2.840.113549.1.1.11";

    public static ReviewerMdsCrlCryptographicCandidate Inspect(
        X509Certificate2? directlyIssuedLeaf,
        X509Certificate2? untrustedDirectIssuer,
        byte[]? externallySuppliedDerCrl,
        DateTimeOffset nowUtc)
    {
        if (directlyIssuedLeaf is null || untrustedDirectIssuer is null ||
            externallySuppliedDerCrl is not { Length: >= 128 and <= MaximumCrlBytes } ||
            nowUtc.Offset != TimeSpan.Zero)
            throw Denied();

        try
        {
            if (untrustedDirectIssuer.Version != 3 ||
                directlyIssuedLeaf.Version != 3 ||
                !HasConstraints(untrustedDirectIssuer, isCa: true) ||
                !HasConstraints(directlyIssuedLeaf, isCa: false) ||
                !HasUsage(untrustedDirectIssuer, X509KeyUsageFlags.KeyCertSign |
                    X509KeyUsageFlags.CrlSign) ||
                !HasUsage(directlyIssuedLeaf, X509KeyUsageFlags.DigitalSignature) ||
                !CertificateIsCurrent(directlyIssuedLeaf, nowUtc) ||
                !CertificateIsCurrent(untrustedDirectIssuer, nowUtc))
                throw Denied();

            // The leaf must actually have been signed directly by this issuer.
            // A custom-root path *without* built-in revocation is used only to
            // confirm this direct signature/path; the independently supplied
            // signed CRL below is checked separately. Never treat this as
            // comprehensive FIDO root, intermediate or OCSP validation.
            using var chain = new X509Chain();
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(untrustedDirectIssuer);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationTime = nowUtc.UtcDateTime;
            if (!chain.Build(directlyIssuedLeaf) ||
                chain.ChainElements.Count != 2 ||
                !CryptographicOperations.FixedTimeEquals(
                    chain.ChainElements[0].Certificate.RawData, directlyIssuedLeaf.RawData) ||
                !CryptographicOperations.FixedTimeEquals(
                    chain.ChainElements[1].Certificate.RawData, untrustedDirectIssuer.RawData))
                throw Denied();

            var issuer = DotNetUtilities.FromX509Certificate(untrustedDirectIssuer);
            var leaf = DotNetUtilities.FromX509Certificate(directlyIssuedLeaf);
            var crl = new X509CrlParser().ReadCrl(externallySuppliedDerCrl);
            if (crl is null ||
                crl.Version != 2 ||
                crl.SigAlgOid != SupportedSignatureOid ||
                !crl.IssuerDN.Equals(issuer.SubjectDN) ||
                !CryptographicOperations.FixedTimeEquals(
                    crl.GetEncoded(), externallySuppliedDerCrl) ||
                crl.GetExtension(X509Extensions.DeltaCrlIndicator) is not null ||
                crl.GetExtension(X509Extensions.IssuingDistributionPoint) is not null ||
                crl.GetExtension(X509Extensions.FreshestCrl) is not null)
                throw Denied();

            // Conservative profile: any critical extensions are unsupported
            // until separately audited; this rejects indirect/delta and
            // unknown critical certificate/CRL processing semantics.
            if (crl.GetCriticalExtensionOids() is { Count: > 0 })
                throw Denied();

            var thisUpdate = DateTime.SpecifyKind(crl.ThisUpdate, DateTimeKind.Utc);
            var nextUpdate = crl.NextUpdate is DateTime next
                ? DateTime.SpecifyKind(next, DateTimeKind.Utc)
                : (DateTime?)null;
            if (nextUpdate is null ||
                thisUpdate > nowUtc.UtcDateTime ||
                nextUpdate.Value <= nowUtc.UtcDateTime ||
                nextUpdate.Value <= thisUpdate ||
                nextUpdate.Value - thisUpdate > MaximumCrlPeriod)
                throw Denied();

            // Verification uses the real CA public key from the *same*
            // certificate that directly signed the leaf, not a CRL-supplied
            // key, host CA store, URL, or an untrusted signing certificate.
            if (!crl.IsSignatureValid(issuer.GetPublicKey()))
                throw Denied();

            var revoked = crl.GetRevokedCertificates();
            if (revoked is { Count: > MaximumRevokedEntries } ||
                revoked is not null && revoked.Any(entry =>
                    entry.GetCriticalExtensionOids() is { Count: > 0 }) ||
                crl.IsRevoked(leaf))
                throw Denied();

            return new ReviewerMdsCrlCryptographicCandidate(
                "UNAPPROVED", "CRL_SIGNATURE_CHECK_ONLY_ROOT_UNTRUSTED",
                Convert.ToHexString(SHA256.HashData(externallySuppliedDerCrl)));
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            throw Denied();
        }
    }

    private static bool CertificateIsCurrent(X509Certificate2 certificate, DateTimeOffset now) =>
        certificate.NotBefore.ToUniversalTime() <= now.UtcDateTime &&
        certificate.NotAfter.ToUniversalTime() > now.UtcDateTime;

    private static bool HasConstraints(X509Certificate2 certificate, bool isCa)
    {
        var extensions = certificate.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        return extensions.Length == 1 && extensions[0].CertificateAuthority == isCa;
    }

    private static bool HasUsage(X509Certificate2 certificate, X509KeyUsageFlags required)
    {
        var extensions = certificate.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        return extensions.Length == 1 &&
            (extensions[0].KeyUsages & required) == required;
    }

    private static UnauthorizedAccessException Denied() =>
        new("Untrusted, revoked, expired or unsupported offline X509 CRL.");
}
