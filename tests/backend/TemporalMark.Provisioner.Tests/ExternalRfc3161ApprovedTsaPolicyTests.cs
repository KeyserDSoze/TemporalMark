using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first RFC3161 reqPolicy and signed TSTInfo policy-binding tests.
/// A matching policy OID does not prove a historically qualified QTSP.
/// </summary>
public sealed class ExternalRfc3161ApprovedTsaPolicyTests
{
    private const string ReviewedPolicyOid = "1.3.6.1.4.1.4146.2.2";
    private const string DummySignerSha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static readonly Uri TsaUri = new("https://tsa.example.invalid/issue");

    [Theory]
    [InlineData("1.3.6.1.4.1.4146.2.2")]
    [InlineData("0.39.2")]
    [InlineData("1.39.3")]
    [InlineData("2.40.3")]
    [InlineData("2.999.1234567890")]
    public void CanonicalOidIsParsedWithoutDisplayNameResolution(string oid)
    {
        var parsed = ExternalRfc3161ApprovedPolicy.ParseRequiredPolicyOid(oid);
        Assert.Equal(oid, parsed.Value);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("1")]
    [InlineData("1.")]
    [InlineData(".1.3.6")]
    [InlineData("1.3.")]
    [InlineData("1..3.6")]
    [InlineData("3.1.2")]
    [InlineData("1.40.2")]
    [InlineData("0.40.2")]
    [InlineData("01.3.6")]
    [InlineData("1.03.6")]
    [InlineData("1.3.06")]
    [InlineData("1.3.6 ")]
    [InlineData(" 1.3.6")]
    [InlineData("1.3.6\n")]
    [InlineData("1.3.+6")]
    [InlineData("1.3.-6")]
    [InlineData("1.3.６")]
    [InlineData("1.3.٦")]
    [InlineData("1.3.4294967296")]
    [InlineData("1.3.9999999999999999999999999999")]
    [InlineData("1.3.6,2.4.5")]
    [InlineData("id-qtst")]
    public void MissingMalformedOrNoncanonicalOidFailsClosed(string? invalid)
    {
        var ex = Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161ApprovedPolicy.ParseRequiredPolicyOid(invalid));
        Assert.Contains("policy", ex.Message, StringComparison.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(invalid) && invalid.Length > 12)
            Assert.DoesNotContain(invalid, ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void OversizedOidIsRejectedBeforeRuntimeOidParsing()
    {
        var huge = "2." + string.Join(".", Enumerable.Repeat("123", 100));
        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161ApprovedPolicy.ParseRequiredPolicyOid(huge));
    }

    [Fact]
    public void SignedTstInfoPolicyMustMatchOperatorApprovedOid()
    {
        var approved = ExternalRfc3161ApprovedPolicy.ParseRequiredPolicyOid(ReviewedPolicyOid);

        ExternalRfc3161ApprovedPolicy.ValidateIssuedPolicy(
            new Oid(ReviewedPolicyOid), approved);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("1.3.6.1.4.1.4146.2.1")]
    [InlineData("1.3.6.1.4.1.4146.2.20")]
    [InlineData("2.999.3")]
    public void WrongOrMissingSignedTstInfoPolicyMustNotYieldReceipt(string? signedPolicy)
    {
        var approved = ExternalRfc3161ApprovedPolicy.ParseRequiredPolicyOid(ReviewedPolicyOid);
        Oid? actual = signedPolicy is null ? null : new Oid(signedPolicy);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161ApprovedPolicy.ValidateIssuedPolicy(actual, approved));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-an-oid")]
    [InlineData("1.3.06")]
    public async Task MissingOrMalformedApprovedPolicyCannotSendHashImprint(string? invalid)
    {
        using var handler = new CapturingHandler();
        using var http = new HttpClient(handler);
        var provider = new ExternalRfc3161TimestampProvider(
            http, TsaUri, "reviewed-operator-tsa",
            approvedSignerCertificateSha256: DummySignerSha256,
            approvedPolicyOid: invalid);

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, handler.Requests);
    }

    [Fact]
    public async Task ActualRfc3161RequestSpecifiesReviewedPolicySha256ImprintNonceAndCertReq()
    {
        using var handler = new CapturingHandler();
        using var http = new HttpClient(handler);
        var imprint = Enumerable.Range(0, 32).Select(n => (byte)n).ToArray();
        var provider = new ExternalRfc3161TimestampProvider(
            http, TsaUri, "reviewed-operator-tsa",
            approvedSignerCertificateSha256: DummySignerSha256,
            approvedPolicyOid: ReviewedPolicyOid);

        await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            provider.RequestAsync(imprint, CancellationToken.None));

        Assert.Equal(1, handler.Requests);
        Assert.NotNull(handler.DerRequest);
        Assert.True(Rfc3161TimestampRequest.TryDecode(
            handler.DerRequest!, out var decoded, out var consumed));
        Assert.NotNull(decoded);
        Assert.Equal(handler.DerRequest!.Length, consumed);
        Assert.Equal(ReviewedPolicyOid, decoded!.RequestedPolicyId?.Value);
        Assert.Equal("2.16.840.1.101.3.4.2.1", decoded.HashAlgorithmId.Value);
        Assert.Equal(imprint, decoded.GetMessageHash().ToArray());
        Assert.NotNull(decoded.GetNonce());
        Assert.True(decoded.RequestSignerCertificate);
    }

    [Fact]
    public async Task DisabledTsaNeedsNoPolicyOrSignerConfiguration()
    {
        using var handler = new CapturingHandler();
        using var http = new HttpClient(handler);
        var provider = new ExternalRfc3161TimestampProvider(
            http, null, "disabled-tsa");

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, handler.Requests);
    }

    private sealed class CapturingHandler : HttpMessageHandler
    {
        public int Requests { get; private set; }
        public byte[]? DerRequest { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests++;
            DerRequest = await request.Content!.ReadAsByteArrayAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.BadGateway);
        }
    }
}
