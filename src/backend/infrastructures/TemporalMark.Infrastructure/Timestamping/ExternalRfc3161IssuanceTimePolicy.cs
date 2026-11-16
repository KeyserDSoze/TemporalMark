using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Pilot-only live HTTP window guard for the *CMS-signed* RFC3161 genTime.
/// The host clock is not qualified UTC, and 120 seconds is an operational
/// tolerance, NOT the token's certified accuracy or revocation evidence.
/// </summary>
public static class ExternalRfc3161IssuanceTimePolicy
{
    public static readonly TimeSpan MaximumLocalClockSkew = TimeSpan.FromSeconds(120);

    private const string ResponseError =
        "The signed RFC 3161 issuance time is inconsistent with the live request interval.";

    public static void ValidateLiveGenTime(
        DateTimeOffset signedGenTime,
        DateTimeOffset requestStartedAt,
        DateTimeOffset responseReceivedAt)
    {
        // DateTimeOffset equality/ordering uses the UTC instant; converting
        // explicitly makes the checks independent of the host local timezone.
        var signedUtc = signedGenTime.ToUniversalTime();
        var startedUtc = requestStartedAt.ToUniversalTime();
        var receivedUtc = responseReceivedAt.ToUniversalTime();

        if (IsExtreme(signedUtc) || IsExtreme(startedUtc) ||
            IsExtreme(receivedUtc) || receivedUtc < startedUtc)
            throw new TimestampProviderResponseException(ResponseError);

        try
        {
            var earliestAllowed = startedUtc - MaximumLocalClockSkew;
            var latestAllowed = receivedUtc + MaximumLocalClockSkew;

            if (signedUtc < earliestAllowed || signedUtc > latestAllowed)
                throw new TimestampProviderResponseException(ResponseError);
        }
        catch (ArgumentOutOfRangeException)
        {
            throw new TimestampProviderResponseException(ResponseError);
        }
    }

    private static bool IsExtreme(DateTimeOffset value) =>
        value == DateTimeOffset.MinValue || value == DateTimeOffset.MaxValue;
}
