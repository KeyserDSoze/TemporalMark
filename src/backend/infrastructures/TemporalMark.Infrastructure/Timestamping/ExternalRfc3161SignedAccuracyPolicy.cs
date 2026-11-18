using System.Security.Cryptography.Pkcs;
using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Strict, UNQUALIFIED delegated-pilot filter for the TSA's CMS-signed
/// RFC3161 TSTInfo.accuracy claim. Does not measure UTC(k) or clock health.
/// </summary>
public static class ExternalRfc3161SignedAccuracyPolicy
{
    public const long MaximumClaimedAccuracyMicroseconds = 1_000_000;
    private const string ResponseError =
        "The signed RFC 3161 timestamp accuracy is absent or outside the approved pilot range.";

    /// <summary>
    /// Call ONLY after independently verifying the RFC3161 CMS signature,
    /// nonce, imprint, signer identity, custom-root path and issuer CRLs.
    /// </summary>
    public static void ValidateVerifiedTokenInfo(Rfc3161TimestampTokenInfo? tokenInfo)
    {
        if (tokenInfo is null)
            throw new TimestampProviderResponseException(ResponseError);

        try
        {
            ValidateSignedAccuracy(tokenInfo.AccuracyInMicroseconds);
        }
        catch (OverflowException)
        {
            // A malicious enormous ASN.1 seconds count could overflow the
            // convenience microseconds conversion. Never return HTTP 500
            // or leak malformed token details for such a response.
            throw new TimestampProviderResponseException(ResponseError);
        }
    }

    /// <summary>
    /// RFC3161 permits omitted accuracy (e.g. expressed by TSA policy).
    /// This deliberately strict pilot requires it in the signed TSTInfo;
    /// zero is accepted only when the nullable field was actually present.
    /// </summary>
    public static void ValidateSignedAccuracy(long? accuracyInMicroseconds)
    {
        if (!accuracyInMicroseconds.HasValue ||
            accuracyInMicroseconds.Value < 0 ||
            accuracyInMicroseconds.Value > MaximumClaimedAccuracyMicroseconds)
            throw new TimestampProviderResponseException(ResponseError);
    }
}
