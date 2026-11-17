using System.Net;
using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first operator-floor guard against rolling a still-fresh issuer-signed
/// full CRL back below a separately reviewed minimum. Static floor !=
/// independent monotonic witness or qualified trust.
/// </summary>
public sealed class ExternalRfc3161CrlNumberFloorTests
{
    private static readonly DateTimeOffset Issuance = DateTimeOffset.UtcNow;

    [Theory]
    [InlineData("1")]
    [InlineData("2")]
    [InlineData("9999999999999999999999999999999999999999")]
    public void CanonicalPositiveIntegerFloorsParse(string raw)
    {
        var approved = ExternalRfc3161IssuerCrlPolicy.ParseRequiredCrlNumberFloor(raw);
        Assert.Equal(BigInteger.Parse(raw), approved);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("0")]
    [InlineData("00")]
    [InlineData("01")]
    [InlineData("+1")]
    [InlineData("-1")]
    [InlineData(" 1")]
    [InlineData("1 ")]
    [InlineData("1.0")]
    [InlineData("1e3")]
    [InlineData("１２")]
    [InlineData("9999999999999999999999999999999999999999999999999999999999999999999")]
    public void MissingAmbiguousOrOversizedFloorsFailClosed(string? raw)
    {
        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ParseRequiredCrlNumberFloor(raw));
    }

    [Fact]
    public void DirectSignerSignedCrlAtOperatorFloorIsAccepted()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var crl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            root, Issuance, crlNumber: new BigInteger(2));

        ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
            signer, root, crl, Issuance, minimumCrlNumber: new BigInteger(2));
    }

    [Fact]
    public void OlderStillFreshCorrectlySignedCrlIsRejectedAgainstOperatorFloor()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var oldCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            root, Issuance, crlNumber: BigInteger.One);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
                signer, root, oldCrl, Issuance, minimumCrlNumber: new BigInteger(2)));
    }

    [Fact]
    public void NewlySignedHigherNumberPassesWithoutIntegerOverflow()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var large = BigInteger.Parse("1208925819614629174706176"); // 2^80
        var crl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            root, Issuance, crlNumber: large);

        ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
            signer, root, crl, Issuance, minimumCrlNumber: large - BigInteger.One);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void BothSignedCrlsHaveSeparateIssuerSpecificFloors(bool rootIsOlder)
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var middle = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(middle);
        var rootCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            root, Issuance, crlNumber: new BigInteger(rootIsOlder ? 1 : 2));
        var middleCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            middle, Issuance, crlNumber: new BigInteger(rootIsOlder ? 4 : 3));

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
                signer, root, new X509Certificate2Collection(middle),
                rootCrl, middleCrl, Issuance,
                rootCrlNumberFloor: new BigInteger(2),
                intermediateCrlNumberFloor: new BigInteger(4)));
    }

    [Fact]
    public void BothSignedCrlsAtTheirIndependentApprovedFloorPass()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var middle = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(middle);
        var rootCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            root, Issuance, crlNumber: new BigInteger(2));
        var middleCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            middle, Issuance, crlNumber: new BigInteger(4));

        ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
            signer, root, new X509Certificate2Collection(middle),
            rootCrl, middleCrl, Issuance,
            rootCrlNumberFloor: new BigInteger(2),
            intermediateCrlNumberFloor: new BigInteger(4));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("01")]
    [InlineData("-1")]
    [InlineData("1 ")]
    public async Task MissingOrInvalidRootFloorRejectsBeforeTsaHttp(string? raw)
    {
        using var capture = new CountingHandler();
        using var http = new HttpClient(capture);
        var tsa = CreateProvider(http, raw);

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            tsa.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, capture.Sends);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("01")]
    [InlineData("+3")]
    public async Task OptionalMiddleCrlWithNoApprovedFloorRejectsBeforeHttp(string? middleFloor)
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        var middleCrl = Convert.ToBase64String(
            ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(root, Issuance));
        using var capture = new CountingHandler();
        using var http = new HttpClient(capture);
        var tsa = CreateProvider(http, "1", middleCrl, middleFloor);

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            tsa.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, capture.Sends);
    }

    [Fact]
    public async Task MiddleFloorWithoutMiddleCrlFailsBeforeHttp()
    {
        using var capture = new CountingHandler();
        using var http = new HttpClient(capture);
        var tsa = CreateProvider(http, "1", null, "2");

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            tsa.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, capture.Sends);
    }

    [Fact]
    public async Task CorrectFloorForSignedTestRootCrlPreservesHttpFailure()
    {
        using var capture = new CountingHandler();
        using var http = new HttpClient(capture);
        var tsa = CreateProvider(http, "1");

        await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            tsa.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(1, capture.Sends);
    }

    [Fact]
    public async Task DisabledTsaDoesNotRequireCrlNumberFloor()
    {
        using var capture = new CountingHandler();
        using var http = new HttpClient(capture);
        var tsa = new ExternalRfc3161TimestampProvider(http, null, "disabled");

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            tsa.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, capture.Sends);
    }

    private static ExternalRfc3161TimestampProvider CreateProvider(
        HttpClient http, string? rootFloor,
        string? middleCrl = null, string? middleFloor = null) => new(
            http, new Uri("https://tsa.example.invalid/issue"), "test-reviewed",
            approvedSignerCertificateSha256:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            approvedPolicyOid: "1.3.6.1.4.1.4146.2.2",
            approvedTrustAnchorCertificateBase64Der: ExternalRfc3161TrustRootTestFixture.Base64Der,
            approvedIssuerCrlBase64Der: ExternalRfc3161TrustRootTestFixture.CrlBase64Der,
            approvedIntermediateIssuerCrlBase64Der: middleCrl,
            approvedRootCrlNumberFloor: rootFloor,
            approvedIntermediateCrlNumberFloor: middleFloor);

    private sealed class CountingHandler : HttpMessageHandler
    {
        internal int Sends { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sends++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadGateway));
        }
    }
}
