using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Strict local, UNQUALIFIED RFC 3161 signer-certificate profile.
/// The verified CMS signer must be an end entity with a key reserved
/// for signing only; this is not proof of QTSP status or private-key custody.
/// </summary>
public static class ExternalRfc3161TsaLeafProfilePolicy
{
    private const string BasicConstraintsOid = "2.5.29.19";
    private const string KeyUsageOid = "2.5.29.15";
    private const string RejectionMessage =
        "The RFC 3161 signer certificate lacks the approved end-entity signing Key Usage profile.";

    public static void Validate(X509Certificate2? signerCertificate)
    {
        if (signerCertificate is null)
            throw new TimestampProviderResponseException(RejectionMessage);

        try
        {
            // The explicit Basic Constraints requirement is a conservative
            // TemporalMark pilot interoperability policy; RFC 5280 itself
            // does not require it on every end-entity certificate.
            var constraints = signerCertificate.Extensions.Cast<X509Extension>()
                .Where(e => string.Equals(e.Oid?.Value, BasicConstraintsOid,
                    StringComparison.Ordinal)).ToArray();
            if (constraints.Length != 1)
                throw new TimestampProviderResponseException(RejectionMessage);

            var basic = new X509BasicConstraintsExtension();
            basic.CopyFrom(constraints[0]);
            if (basic.CertificateAuthority || basic.HasPathLengthConstraint)
                throw new TimestampProviderResponseException(RejectionMessage);

            // Restrict both critical and noncritical Key Usage to the
            // two RFC 5280 signature-purpose bits. A CA/CRL/encryption
            // bit would make this key share another certified purpose.
            var usages = signerCertificate.Extensions.Cast<X509Extension>()
                .Where(e => string.Equals(e.Oid?.Value, KeyUsageOid,
                    StringComparison.Ordinal)).ToArray();
            if (usages.Length != 1)
                throw new TimestampProviderResponseException(RejectionMessage);

            var usage = new X509KeyUsageExtension();
            usage.CopyFrom(usages[0]);
            var allowed = X509KeyUsageFlags.DigitalSignature |
                          X509KeyUsageFlags.NonRepudiation;
            if ((usage.KeyUsages & allowed) == 0 ||
                (usage.KeyUsages & ~allowed) != 0)
                throw new TimestampProviderResponseException(RejectionMessage);
        }
        catch (CryptographicException)
        {
            throw new TimestampProviderResponseException(RejectionMessage);
        }
    }
}
