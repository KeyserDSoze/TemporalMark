using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Checks only RFC 3161 §2.3's strict TSA signer EKU profile after the
/// RFC 3161 CMS signature and hash have been verified. This DOES NOT
/// validate chain, revocation, qualified service status or legal trust.
/// </summary>
public static class ExternalRfc3161SignerCertificatePolicy
{
    private const string ExtendedKeyUsageOid = "2.5.29.37";
    private const string TimeStampingKeyPurposeOid = "1.3.6.1.5.5.7.3.8";
    private const string RejectionMessage =
        "RFC 3161 signer certificate requires one critical, exclusive time-stamping EKU.";

    public static void Validate(X509Certificate2? signerCertificate)
    {
        if (signerCertificate is null)
            throw new TimestampProviderResponseException(RejectionMessage);

        // RFC3161 §2.3 requires *one extension instance*, critical, whose
        // sole key-purpose OID is id-kp-timeStamping. Mere inclusion is not
        // enough and is distinct from Windows/.NET's permissive EKU checks.
        var ekuExtensions = signerCertificate.Extensions
            .Cast<X509Extension>()
            .Where(extension => string.Equals(
                extension.Oid?.Value, ExtendedKeyUsageOid, StringComparison.Ordinal))
            .ToArray();

        if (ekuExtensions.Length != 1 || !ekuExtensions[0].Critical)
            throw new TimestampProviderResponseException(RejectionMessage);

        try
        {
            var parsed = new X509EnhancedKeyUsageExtension();
            parsed.CopyFrom(ekuExtensions[0]);

            var purposes = parsed.EnhancedKeyUsages;
            if (purposes.Count != 1 ||
                !string.Equals(purposes[0]?.Value, TimeStampingKeyPurposeOid,
                    StringComparison.Ordinal))
                throw new TimestampProviderResponseException(RejectionMessage);
        }
        catch (CryptographicException)
        {
            // Never return raw malformed ASN.1 or certificate metadata to the caller.
            throw new TimestampProviderResponseException(RejectionMessage);
        }
    }
}
