using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first: an intermediate CA and the TSA leaf require two separate
/// genuinely issuer-signed full CRLs, selected by an already verified path.
/// Disposable certificates and CRLs are NOT real QTSP evidence.
/// </summary>
public sealed class ExternalRfc3161TwoHopIssuerCrlTests
{
    private static readonly DateTimeOffset SignedGenTime = DateTimeOffset.UtcNow;

    [Fact]
    public void VerifiedThreeCertificatePathWithBothCleanSignedCrlsPasses()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var middle = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(middle);
        var rootCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(root, SignedGenTime);
        var middleCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(middle, SignedGenTime);

        ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
            signer, root, new X509Certificate2Collection(middle),
            rootCrl, middleCrl, SignedGenTime);

        using var validated = ExternalRfc3161CertificateChainPolicy.BuildValidatedSignerChain(
            signer, root, new X509Certificate2Collection(middle), SignedGenTime);
        Assert.Equal(3, validated.ChainElements.Count);
        Assert.Equal(middle.RawData, validated.ChainElements[1].Certificate.RawData);
        Assert.Equal(root.RawData, validated.ChainElements[2].Certificate.RawData);
    }

    [Fact]
    public void SignedRootCrlListingIntermediateFailsEvenWithCleanLeafCrl()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var middle = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(middle);
        var revokedMiddle = new CertificateRevocationListBuilder();
        revokedMiddle.AddEntry(middle, SignedGenTime.AddMinutes(-3));
        var rootCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            root, SignedGenTime, revokedMiddle);
        var middleCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(middle, SignedGenTime);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
                signer, root, new X509Certificate2Collection(middle),
                rootCrl, middleCrl, SignedGenTime));
    }

    [Fact]
    public void SignedMiddleCrlListingTsaSignerFailsEvenWithCleanRootCrl()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var middle = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(middle);
        var revokedSigner = new CertificateRevocationListBuilder();
        revokedSigner.AddEntry(signer, SignedGenTime.AddMinutes(2));
        var rootCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(root, SignedGenTime);
        var middleCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            middle, SignedGenTime, revokedSigner);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
                signer, root, new X509Certificate2Collection(middle),
                rootCrl, middleCrl, SignedGenTime));
    }

    [Fact]
    public void MissingOrMalformedMiddleCrlCannotTurnIntoNoCheck()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var middle = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(middle);
        var rootCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(root, SignedGenTime);
        byte[] malformed = [0x05, 0x00];

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
                signer, root, new X509Certificate2Collection(middle),
                rootCrl, ReadOnlyMemory<byte>.Empty, SignedGenTime));
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
                signer, root, new X509Certificate2Collection(middle),
                rootCrl, malformed, SignedGenTime));
    }

    [Fact]
    public void WrongMiddleSigningKeyWithSameIssuerDnCannotAttestLeaf()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var actualMiddle = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var impostorMiddle = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(actualMiddle);
        var rootCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(root, SignedGenTime);
        var impostorCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            impostorMiddle, SignedGenTime);

        // Both middle CAs share an X.500 name; only one is on the
        // certificate-signature-validated chain.
        var cmsCertificates = new X509Certificate2Collection();
        cmsCertificates.Add(actualMiddle);
        cmsCertificates.Add(impostorMiddle);
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
                signer, root, cmsCertificates,
                rootCrl, impostorCrl, SignedGenTime));
    }

    [Fact]
    public void ExpiredMiddleCrlRejectsEvenWithFreshRootCrl()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var middle = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(middle);
        var rootCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(root, SignedGenTime);
        var expiredMiddle = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            middle, SignedGenTime,
            thisUpdate: SignedGenTime.AddDays(-3),
            nextUpdate: SignedGenTime.AddDays(-1));

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
                signer, root, new X509Certificate2Collection(middle),
                rootCrl, expiredMiddle, SignedGenTime));
    }

    [Fact]
    public void NotYetEffectiveRootCrlRejectsEvenWithFreshMiddleCrl()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var middle = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(middle);
        var futureRoot = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(
            root, SignedGenTime,
            thisUpdate: SignedGenTime.AddHours(1),
            nextUpdate: SignedGenTime.AddDays(1));
        var middleCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(middle, SignedGenTime);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
                signer, root, new X509Certificate2Collection(middle),
                futureRoot, middleCrl, SignedGenTime));
    }

    [Fact]
    public void MissingActualMiddleCertificateCannotBeSolvedByCorrectTwoCrls()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var middle = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(middle);
        var rootCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(root, SignedGenTime);
        var middleCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(middle, SignedGenTime);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
                signer, root, new X509Certificate2Collection(),
                rootCrl, middleCrl, SignedGenTime));
    }

    [Fact]
    public void DirectRootIssuedSignerRemainsAcceptedWithOnlyRootCrl()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var rootCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(root, SignedGenTime);

        ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
            signer, root, new X509Certificate2Collection(),
            rootCrl, ReadOnlyMemory<byte>.Empty, SignedGenTime);
    }

    [Fact]
    public void DirectSignerCannotSilentlyIgnoreExtraIntermediateCrl()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var rootCrl = ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(root, SignedGenTime);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateSignerPathRevocation(
                signer, root, new X509Certificate2Collection(),
                rootCrl, rootCrl, SignedGenTime));
    }

    [Fact]
    public async Task InvalidConfiguredMiddleCrlIsRejectedBeforeAnyTsaRequest()
    {
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var tsa = CreateProvider(http, "invalid-middle-crl!");

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            tsa.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, handler.Sends);
    }

    [Fact]
    public async Task WellFormedOptionalMiddleCrlKeepsPriorHttpEnvelopeFailure()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        var optionalCrl = Convert.ToBase64String(
            ExternalRfc3161IssuerCrlPolicyTests.BuildCrl(root, SignedGenTime));
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var tsa = CreateProvider(http, optionalCrl);

        await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            tsa.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(1, handler.Sends);
    }

    [Fact]
    public async Task MissingOptionalMiddleCrlPreservesDirectRootIssuedSend()
    {
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var tsa = CreateProvider(http, null);

        await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            tsa.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(1, handler.Sends);
    }

    private static ExternalRfc3161TimestampProvider CreateProvider(
        HttpClient http, string? middleCrl) => new(
            http, new Uri("https://tsa.example.invalid/issue"), "reviewed-test-issuer",
            approvedSignerCertificateSha256:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            approvedPolicyOid: "1.3.6.1.4.1.4146.2.2",
            approvedTrustAnchorCertificateBase64Der: ExternalRfc3161TrustRootTestFixture.Base64Der,
            approvedIssuerCrlBase64Der: ExternalRfc3161TrustRootTestFixture.CrlBase64Der,
            approvedIntermediateIssuerCrlBase64Der: middleCrl);

    private sealed class CountingHandler : HttpMessageHandler
    {
        public int Sends { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sends++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadGateway));
        }
    }
}
