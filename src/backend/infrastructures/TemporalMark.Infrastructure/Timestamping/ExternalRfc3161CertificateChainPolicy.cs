using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Offline, operator-anchored current-time PKIX path check for the *verified*
/// RFC3161 CMS signer. Revocation, historical EU Trusted Lists and legal QTSP
/// qualification are NOT established by this policy.
/// </summary>
public static class ExternalRfc3161CertificateChainPolicy
{
    private const int MaximumAnchorDerBytes = 65_536;
    private const string ConfigurationError =
        "An operator-approved RFC 3161 X.509 CA trust anchor in canonical Base64 DER is required.";
    private const string ResponseError =
        "The RFC 3161 signer does not build a valid offline path to the approved CA root.";

    public static X509Certificate2 ParseRequiredAnchorBase64Der(string? base64Der)
    {
        // Strict, bounded, single DER-encoded X.509 root; never silently
        // normalize whitespace, accept PEM/PKCS#12, or load system trust.
        if (string.IsNullOrEmpty(base64Der) ||
            base64Der.Length > ((MaximumAnchorDerBytes + 2) / 3) * 4 ||
            base64Der.Length % 4 != 0)
            throw new TimestampProviderUnavailableException(ConfigurationError);

        foreach (var c in base64Der)
        {
            if (!((c is >= 'A' and <= 'Z') ||
                  (c is >= 'a' and <= 'z') ||
                  (c is >= '0' and <= '9') ||
                  c is '+' or '/' or '='))
                throw new TimestampProviderUnavailableException(ConfigurationError);
        }

        try
        {
            var der = Convert.FromBase64String(base64Der);
            if (der.Length == 0 || der.Length > MaximumAnchorDerBytes ||
                !string.Equals(Convert.ToBase64String(der), base64Der,
                    StringComparison.Ordinal))
                throw new TimestampProviderUnavailableException(ConfigurationError);

            var anchor = X509CertificateLoader.LoadCertificate(der);
            if (!anchor.RawData.AsSpan().SequenceEqual(der) ||
                !anchor.SubjectName.RawData.AsSpan()
                    .SequenceEqual(anchor.IssuerName.RawData))
            {
                anchor.Dispose();
                throw new TimestampProviderUnavailableException(ConfigurationError);
            }

            var basicConstraints = anchor.Extensions
                .Cast<X509Extension>()
                .Where(x => x.Oid?.Value == "2.5.29.19").ToArray();
            var keyUsages = anchor.Extensions
                .Cast<X509Extension>()
                .Where(x => x.Oid?.Value == "2.5.29.15").ToArray();

            try
            {
                if (basicConstraints.Length != 1 ||
                    !basicConstraints[0].Critical ||
                    basicConstraints[0] is not X509BasicConstraintsExtension
                        { CertificateAuthority: true } ||
                    keyUsages.Length != 1 || !keyUsages[0].Critical ||
                    keyUsages[0] is not X509KeyUsageExtension keyUsage ||
                    !keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
                    throw new TimestampProviderUnavailableException(ConfigurationError);
            }
            catch
            {
                anchor.Dispose();
                throw;
            }

            return anchor;
        }
        catch (CryptographicException)
        {
            throw new TimestampProviderUnavailableException(ConfigurationError);
        }
        catch (FormatException)
        {
            throw new TimestampProviderUnavailableException(ConfigurationError);
        }
        catch (ArgumentException)
        {
            throw new TimestampProviderUnavailableException(ConfigurationError);
        }
    }

    /// <summary>
    /// A new chain with the operator's one root, no AIA/CRL/OCSP network
    /// activity, no ignored verification errors, and no system CA fallback.
    /// NoCheck is deliberate: it must never be interpreted as revocation proof.
    /// </summary>
    public static X509Chain CreateOfflineChain(
        X509Certificate2 approvedRoot,
        X509Certificate2Collection cmsCertificates)
    {
        ArgumentNullException.ThrowIfNull(approvedRoot);
        ArgumentNullException.ThrowIfNull(cmsCertificates);

        var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(approvedRoot);
        chain.ChainPolicy.ExtraStore.AddRange(cmsCertificates);
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.VerificationTime = DateTime.UtcNow;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.8"));
        return chain;
    }

    public static void ValidateSignerChain(
        X509Certificate2? verifiedSigner,
        X509Certificate2 approvedRoot,
        X509Certificate2Collection cmsCertificates)
    {
        if (verifiedSigner is null || approvedRoot is null || cmsCertificates is null)
            throw new TimestampProviderResponseException(ResponseError);

        try
        {
            using var chain = CreateOfflineChain(approvedRoot, cmsCertificates);
            if (!chain.Build(verifiedSigner) || chain.ChainElements.Count < 2)
                throw new TimestampProviderResponseException(ResponseError);

            // The path must really terminate at the exact reviewed DER root,
            // never at a system anchor with a similar subject / same key.
            var elements = chain.ChainElements;
            if (!CryptographicOperations.FixedTimeEquals(
                    elements[elements.Count - 1].Certificate.RawData, approvedRoot.RawData))
                throw new TimestampProviderResponseException(ResponseError);

            // The OS may have cached intermediary certificates, even when
            // issuer downloads are disabled. Only intermediates actually
            // embedded in this RFC3161 CMS response are permitted to build
            // this application's independent chain.
            for (var i = 1; i < elements.Count - 1; i++)
            {
                var certDer = elements[i].Certificate.RawData;
                if (!cmsCertificates.Cast<X509Certificate2>().Any(c =>
                        CryptographicOperations.FixedTimeEquals(c.RawData, certDer)))
                    throw new TimestampProviderResponseException(ResponseError);
            }
        }
        catch (CryptographicException)
        {
            throw new TimestampProviderResponseException(ResponseError);
        }
    }
}
