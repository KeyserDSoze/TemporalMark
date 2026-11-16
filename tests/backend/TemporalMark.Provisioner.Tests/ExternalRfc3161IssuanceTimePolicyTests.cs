using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first live issue-clock consistency. The operator's host clock is
/// NOT qualified UTC, and a correctly signed genTime is not independently
/// witnessed by this policy.
/// </summary>
public sealed class ExternalRfc3161IssuanceTimePolicyTests
{
    private static readonly DateTimeOffset RequestStart =
        new(2026, 11, 16, 20, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset ResponseReceived =
        RequestStart.AddSeconds(18);

    [Theory]
    [InlineData(-120)]
    [InlineData(-119)]
    [InlineData(-1)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(18)]
    [InlineData(19)]
    [InlineData(137)]
    [InlineData(138)]
    public void WindowIncludingBothClockToleranceBoundariesIsAccepted(int secondsFromStart)
    {
        // Response end is 18s after request start, so +138s is exact upper bound.
        ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime(
            RequestStart.AddSeconds(secondsFromStart), RequestStart, ResponseReceived);
    }

    [Theory]
    [InlineData(-121)]
    [InlineData(-600)]
    [InlineData(139)]
    [InlineData(600)]
    public void TooStaleOrFutureSignedGenTimeFailsClosed(int secondsFromStart)
    {
        var exception = Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime(
                RequestStart.AddSeconds(secondsFromStart), RequestStart, ResponseReceived));

        Assert.DoesNotContain("2026", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ReceiptBeforeRequestStartIndicatesClockReversalAndFailsClosed()
    {
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime(
                RequestStart, RequestStart, RequestStart.AddTicks(-1)));
    }

    [Fact]
    public void ZeroDurationRequestIsAllowedWithinSameBoundedWindow()
    {
        ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime(
            RequestStart, RequestStart, RequestStart);
    }

    [Fact]
    public void OffsetsMustCompareOnUtcInstantNotTextualLocalWallTime()
    {
        var asRome = RequestStart.ToOffset(TimeSpan.FromHours(1));
        var asNewYork = ResponseReceived.ToOffset(TimeSpan.FromHours(-5));
        var signedRome = RequestStart.AddSeconds(10).ToOffset(TimeSpan.FromHours(1));

        ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime(
            signedRome, asRome, asNewYork);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ExtremeBoundaryTimesAreRejectedWithoutOverflow(bool earliest)
    {
        var extreme = earliest ? DateTimeOffset.MinValue : DateTimeOffset.MaxValue;

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime(
                extreme, RequestStart, ResponseReceived));
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime(
                RequestStart, extreme, ResponseReceived));
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime(
                RequestStart, RequestStart, extreme));
    }

    [Fact]
    public void DefaultTimestampCannotBeAcceptedAsFreshIssuance()
    {
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime(
                default, RequestStart, ResponseReceived));
    }

    [Fact]
    public void WideIntervalStillDoesNotAllowOlderThanRequestStartMinusSkew()
    {
        var slowResponse = RequestStart.AddMinutes(3);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuanceTimePolicy.ValidateLiveGenTime(
                RequestStart.AddMinutes(-3), RequestStart, slowResponse));
    }
}
