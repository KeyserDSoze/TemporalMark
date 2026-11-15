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
/// Strict, offline DER X509 v2 full-CRL proof for one directly issued
/// certificate, not an MDS trust or authorization interface. ADR 0030.
/// The shared internal certificate+CRL check is reused by the two-hop
/// inspection (ADR 0031) without creating a separate signature verifier.
/// </summary>
public static class ReviewerMdsOfflineCrlCandidateVerifier
{
    private const int MaximumCrlBytes = 1_048_576;
    private const int MaximumRevokedEntries = 10000;
    private static readonly TimeSpan MaximumCrlPeriod = TimeSpan.FromDays(7);
    // SHA256WITHRSA only for this deliberately narrow test profile.
    private const string SupportedSignatureOid = "1.2.840.113549.1.1.11";

    public static ReviewerMdsCrlCryptographicCandidate Inspect(
        X509Certificate2? directlyIssuedLeaf,
        X509Certificate2? untrustedDirectIssuer,
        byte[]? externallySuppliedDerCrl,
        DateTimeOffset nowUtc)
    {
        if (directlyIssuedLeaf is null || untrustedDirectIssuer is null)
            throw Denied();

        try
        {
            // Complete the same signed CRL inspection shared by #60.
            var digest = VerifySignedDirectCrl(
                directlyIssuedLeaf, untrustedDirectIssuer,
                externallySuppliedDerCrl, nowUtc, subjectIsCa: false);

            // Check actual one-hop X509 certificate signature and byte-exact
            // issuer. No host trust, downloads, optional revocation or
            // fallback; NoCheck applies ONLY to path cryptography because
            // we independently verified the exact issuer-signed CRL above.
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

            return new ReviewerMdsCrlCryptographicCandidate(
                "UNAPPROVED", "CRL_SIGNATURE_CHECK_ONLY_ROOT_UNTRUSTED", digest);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            throw Denied();
        }
    }

    /// <summary>
    /// Checks one explicit direct-issuer signed CRL without deciding whether
    /// the issuer belongs to an approved trust chain. This is not an
    /// authorization or an issuer-root trust result. Used ONLY after an
    /// independent exact X509 path check in the two-hop test preflight.
    /// </summary>
    internal static string VerifySignedDirectCrl(
        X509Certificate2? subject,
        X509Certificate2? untrustedIssuer,
        byte[]? externallySuppliedDerCrl,
        DateTimeOffset nowUtc,
        bool subjectIsCa)
    {
        if (subject is null || untrustedIssuer is null ||
            externallySuppliedDerCrl is not { Length: >= 128 and <= MaximumCrlBytes } ||
            nowUtc.Offset != TimeSpan.Zero)
            throw Denied();

        try
        {
            if (untrustedIssuer.Version != 3 || subject.Version != 3 ||
                !HasConstraints(untrustedIssuer, isCa: true) ||
                !HasConstraints(subject, isCa: subjectIsCa) ||
                !HasUsage(untrustedIssuer,
                    X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign) ||
                !HasUsage(subject, subjectIsCa
                    ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign
                    : X509KeyUsageFlags.DigitalSignature) ||
                !CertificateIsCurrent(subject, nowUtc) ||
                !CertificateIsCurrent(untrustedIssuer, nowUtc))
                throw Denied();

            var issuer = DotNetUtilities.FromX509Certificate(untrustedIssuer);
            var leaf = DotNetUtilities.FromX509Certificate(subject);
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

            // No unknown critical/delta/indirect CRL processing until a
            // separately approved complete RFC 5280 implementation exists.
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

            // Verify against the public key in the SAME CA that issued the
            // subject certificate, not an untrusted CRL-provided cert/key.
            if (!crl.IsSignatureValid(issuer.GetPublicKey()))
                throw Denied();

            var revoked = crl.GetRevokedCertificates();
            if (revoked is { Count: > MaximumRevokedEntries } ||
                revoked is not null && revoked.Any(entry =>
                    entry.GetCriticalExtensionOids() is { Count: > 0 }) ||
                crl.IsRevoked(leaf))
                throw Denied();

            // A digest cannot be evidence of root trust or persistent
            // anti-rollback; it is non-authorizing cryptographic metadata.
            return Convert.ToHexString(SHA256.HashData(externallySuppliedDerCrl));
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
