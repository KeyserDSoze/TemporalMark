using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first #98: a strict claimed-accuracy filter on the already verified
/// CMS-signed TSTInfo. Encoded TSTInfo alone is NOT a signed timestamp.
/// </summary>
public sealed class ExternalRfc3161SignedAccuracyPolicyTests
{
    [Theory]
    [InlineData(0L)]
    [InlineData(1L)]
    [InlineData(500_000L)]
    [InlineData(999_999L)]
    [InlineData(1_000_000L)]
    public void ExplicitAccuracyAtOrBelowOneSecondIsAccepted(long micros)
    {
        ExternalRfc3161SignedAccuracyPolicy.ValidateSignedAccuracy(micros);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(-1L)]
    [InlineData(1_000_001L)]
    [InlineData(60_000_000L)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    public void AbsentNegativeOrExcessiveClaimFailsClosed(long? micros)
    {
        var error = Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161SignedAccuracyPolicy.ValidateSignedAccuracy(micros));
        Assert.Contains("accuracy", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("1000001", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ActualDerTstInfoAccuracyIsReadByDotnetBeforeStrictGate()
    {
        // Genuine ASN.1 TSTInfo encode/decode; it has NO CMS signature
        // and by itself cannot authorize a TimestampRecord or trust status.
        var claimed = CreateInfo(500_000L);
        var encoded = claimed.Encode();
        Assert.True(Rfc3161TimestampTokenInfo.TryDecode(
            encoded, out var decoded, out var consumed));
        Assert.Equal(encoded.Length, consumed);
        Assert.NotNull(decoded);
        Assert.Equal(500_000L, decoded.AccuracyInMicroseconds);
        ExternalRfc3161SignedAccuracyPolicy.ValidateSignedAccuracy(
            decoded.AccuracyInMicroseconds);
    }

    [Fact]
    public void Rfc3161AllowsOmittedAccuracyButStrictPilotMustRejectIt()
    {
        var claimed = CreateInfo(null);
        var encoded = claimed.Encode();
        Assert.True(Rfc3161TimestampTokenInfo.TryDecode(
            encoded, out var decoded, out var consumed));
        Assert.Equal(encoded.Length, consumed);
        Assert.NotNull(decoded);
        Assert.Null(decoded.AccuracyInMicroseconds);
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161SignedAccuracyPolicy.ValidateSignedAccuracy(
                decoded.AccuracyInMicroseconds));
    }

    private static Rfc3161TimestampTokenInfo CreateInfo(long? accuracy) => new(
        new Oid("1.3.6.1.4.1.4146.2.2"),
        new Oid("2.16.840.1.101.3.4.2.1"),
        new byte[32],
        new byte[] { 0x01 },
        new DateTimeOffset(2026, 11, 18, 8, 0, 0, TimeSpan.Zero),
        accuracyInMicroseconds: accuracy);
}
