using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first #100: unknown signed TSTInfo extension semantics cannot
/// silently pass this conservative unqualified pilot. The DER TSTInfo
/// fixtures are deliberately UNSIGNED, not legitimate QTSP evidence.
/// </summary>
public sealed class ExternalRfc3161TstInfoExtensionPolicyTests
{
    [Fact]
    public void GenuineDerTstInfoWithNoExtensionsPassesPilotProfile()
    {
        var info = EncodeAndDecode(null); // RFC3161 optional extensions ABSENT
        Assert.False(info.HasExtensions);
        Assert.Empty(info.GetExtensions());
        ExternalRfc3161TstInfoExtensionPolicy.ValidateVerifiedTokenInfo(info);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void GenuineDerTstInfoWithUnknownNoncriticalOrCriticalExtensionIsDenied(
        bool critical)
    {
        var info = EncodeAndDecode(CreateExtensions(("1.3.6.1.4.1.55555.100", critical)));
        Assert.True(info.HasExtensions);
        Assert.Single(info.GetExtensions());

        var error = Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161TstInfoExtensionPolicy.ValidateVerifiedTokenInfo(info));
        Assert.Contains("extension", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("55555", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TwoDistinctCriticalityMixedDerTstInfoExtensionsAreDenied()
    {
        var info = EncodeAndDecode(CreateExtensions(
            ("1.3.6.1.4.1.55555.100", false),
            ("1.3.6.1.4.1.55555.101", true)));
        Assert.True(info.HasExtensions);
        Assert.Equal(2, info.GetExtensions().Count);
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161TstInfoExtensionPolicy.ValidateVerifiedTokenInfo(info));
    }

    [Fact]
    public void AbsentTokenInfoIsDeniedWithoutNullReferenceOrDisclosure()
    {
        var error = Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161TstInfoExtensionPolicy.ValidateVerifiedTokenInfo(null));
        Assert.Contains("extension", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static X509ExtensionCollection CreateExtensions(
        params (string Oid, bool Critical)[] specifications)
    {
        var result = new X509ExtensionCollection();
        foreach (var item in specifications)
            result.Add(new X509Extension(
                new Oid(item.Oid), new byte[] { 0x05, 0x00 }, item.Critical));
        return result;
    }

    private static Rfc3161TimestampTokenInfo EncodeAndDecode(X509ExtensionCollection? extensions)
    {
        var unsigned = new Rfc3161TimestampTokenInfo(
            new Oid("1.3.6.1.4.1.4146.2.2"),
            new Oid("2.16.840.1.101.3.4.2.1"),
            new byte[32],
            new byte[] { 0x01 },
            new DateTimeOffset(2026, 11, 18, 9, 0, 0, TimeSpan.Zero),
            accuracyInMicroseconds: 500_000L,
            extensions: extensions);
        var bytes = unsigned.Encode();
        Assert.True(Rfc3161TimestampTokenInfo.TryDecode(
            bytes, out var decoded, out var consumed));
        Assert.Equal(bytes.Length, consumed);
        Assert.NotNull(decoded);
        return decoded;
    }
}
