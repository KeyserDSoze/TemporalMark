using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first: bind the verified RFC 3161 CMS signer to a previously reviewed
/// operator-configured SHA-256 DER certificate fingerprint. Self-signed test
/// certificates are UNTRUSTED fixtures and do not establish QTSP status.
/// </summary>
public sealed class ExternalRfc3161SignerPinPolicyTests
{
    private const string ExampleSha256Pin =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static readonly Uri TestEndpoint = new("https://tsa.example.invalid/issue");

    [Fact]
    public void ReviewedSignerCertificateDerSha256IsAccepted()
    {
        using var signer = CreateDisposableCertificate();
        var expected = signer.GetCertHash(HashAlgorithmName.SHA256);
        var pin = Convert.ToHexString(expected);

        var parsed = ExternalRfc3161SignerPinPolicy.ParseRequiredSha256(pin);

        Assert.Equal(32, parsed.Length);
        Assert.Equal(expected, parsed);
        ExternalRfc3161SignerPinPolicy.ValidateVerifiedSigner(signer, parsed);
    }

    [Fact]
    public void LowercaseHexHasIdenticalMeaning()
    {
        using var signer = CreateDisposableCertificate();
        var lower = Convert.ToHexString(signer.GetCertHash(HashAlgorithmName.SHA256))
            .ToLowerInvariant();

        ExternalRfc3161SignerPinPolicy.ValidateVerifiedSigner(
            signer, ExternalRfc3161SignerPinPolicy.ParseRequiredSha256(lower));
    }

    [Fact]
    public void CryptographicallySelfConsistentUnreviewedSignerMustBeRejected()
    {
        using var approvedSigner = CreateDisposableCertificate();
        using var attackerSigner = CreateDisposableCertificate();
        var approvedPin = Convert.ToHexString(
            approvedSigner.GetCertHash(HashAlgorithmName.SHA256));
        var bytes = ExternalRfc3161SignerPinPolicy.ParseRequiredSha256(approvedPin);

        Assert.NotEqual(
            approvedSigner.GetCertHash(HashAlgorithmName.SHA256),
            attackerSigner.GetCertHash(HashAlgorithmName.SHA256));
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161SignerPinPolicy.ValidateVerifiedSigner(attackerSigner, bytes));
    }

    [Fact]
    public void NullVerifiedCmsSignerMustBeRejected()
    {
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161SignerPinPolicy.ValidateVerifiedSigner(null, new byte[32]));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(20)]
    [InlineData(31)]
    [InlineData(33)]
    public void InvalidSha256PinByteLengthCannotBeAnApproval(int length)
    {
        using var signer = CreateDisposableCertificate();
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161SignerPinPolicy.ValidateVerifiedSigner(signer, new byte[length]));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("abcdef")]
    [InlineData("0123456789abcdef0123456789abcdef01234567")]
    [InlineData("0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ")]
    [InlineData(" 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeG")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeé")]
    [InlineData("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,0123")]
    public void MissingMalformedAndAmbiguousHexCannotEnableTsa(string? malformed)
    {
        var error = Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161SignerPinPolicy.ParseRequiredSha256(malformed));

        Assert.Contains("SHA-256", error.Message, StringComparison.OrdinalIgnoreCase);
        // The generic rejection message naturally includes spaces; only
        // assert redaction for substantive supplied fingerprint-like values.
        if (!string.IsNullOrWhiteSpace(malformed) && malformed.Length >= 32)
            Assert.DoesNotContain(malformed, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void ColonSeparatedHumanDisplayFingerprintIsNotAcceptedConfiguration()
    {
        var formatted = string.Join(":", Enumerable.Range(0, 32).Select(i => i.ToString("x2")));

        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161SignerPinPolicy.ParseRequiredSha256(formatted));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not-hex")]
    [InlineData("AABBCCDD")]
    public async Task NoApprovedSignerIdentityMustFailBeforeAnyNetworkSend(string? pin)
    {
        using var spy = new CountingHandler();
        using var http = new HttpClient(spy);
        var provider = new ExternalRfc3161TimestampProvider(
            http, TestEndpoint, "operator-approved-identity", approvedSignerCertificateSha256: pin,
            approvedPolicyOid: "1.3.6.1.4.1.4146.2.2",
            approvedTrustAnchorCertificateBase64Der: ExternalRfc3161TrustRootTestFixture.Base64Der,
            approvedIssuerCrlBase64Der: ExternalRfc3161TrustRootTestFixture.CrlBase64Der);

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, spy.Sends);
    }

    [Fact]
    public async Task WellFormedApprovedPinDoesNotDisableExistingHttpEnvelopeChecks()
    {
        using var spy = new CountingHandler();
        using var http = new HttpClient(spy);
        var provider = new ExternalRfc3161TimestampProvider(
            http, TestEndpoint, "operator-approved-identity",
            approvedSignerCertificateSha256: ExampleSha256Pin,
            approvedPolicyOid: "1.3.6.1.4.1.4146.2.2",
            approvedTrustAnchorCertificateBase64Der: ExternalRfc3161TrustRootTestFixture.Base64Der,
            approvedIssuerCrlBase64Der: ExternalRfc3161TrustRootTestFixture.CrlBase64Der);

        await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(1, spy.Sends);
    }

    [Fact]
    public async Task DisabledTsaStillHasNoSignerPinRequirement()
    {
        using var spy = new CountingHandler();
        using var http = new HttpClient(spy);
        var provider = new ExternalRfc3161TimestampProvider(
            http, null, "disabled-provider");

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, spy.Sends);
    }

    private static X509Certificate2 CreateDisposableCertificate()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Disposable untrusted RFC3161 signer identity fixture",
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddHours(-1),
            DateTimeOffset.UtcNow.AddHours(1));
    }

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
