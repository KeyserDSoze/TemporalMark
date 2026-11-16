using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Requires an explicitly operator-approved SHA-256 fingerprint of the whole
/// DER RFC 3161 signing certificate. This is NOT PKIX path validation,
/// historical revocation or an EU qualified trust service assessment.
/// </summary>
public static class ExternalRfc3161SignerPinPolicy
{
    private const string ConfigurationError =
        "A valid operator-approved TSA signer certificate SHA-256 fingerprint is required.";
    private const string SignerError =
        "The RFC 3161 signer certificate does not match the approved TSA SHA-256 fingerprint.";

    /// <summary>
    /// Accept exactly 32 bytes encoded as 64 ASCII hexadecimal characters.
    /// Never silently trim, accept SHA-1, or parse a list of fallback pins.
    /// </summary>
    public static byte[] ParseRequiredSha256(string? approvedCertificateSha256)
    {
        if (approvedCertificateSha256 is null || approvedCertificateSha256.Length != 64)
            throw new TimestampProviderUnavailableException(ConfigurationError);

        foreach (var value in approvedCertificateSha256)
        {
            if (!((value >= '0' && value <= '9') ||
                  (value >= 'a' && value <= 'f') ||
                  (value >= 'A' && value <= 'F')))
                throw new TimestampProviderUnavailableException(ConfigurationError);
        }

        return Convert.FromHexString(approvedCertificateSha256);
    }

    /// <summary>
    /// Invoke only on the cryptographically verified CMS signer. Never use
    /// any unrelated X.509 certificate included in the TSA response.
    /// </summary>
    public static void ValidateVerifiedSigner(
        X509Certificate2? verifiedSigner,
        ReadOnlySpan<byte> approvedCertificateSha256)
    {
        if (verifiedSigner is null || approvedCertificateSha256.Length != 32)
            throw new TimestampProviderResponseException(SignerError);

        var actualSha256 = verifiedSigner.GetCertHash(HashAlgorithmName.SHA256);
        if (!CryptographicOperations.FixedTimeEquals(actualSha256, approvedCertificateSha256))
            throw new TimestampProviderResponseException(SignerError);
    }
}
