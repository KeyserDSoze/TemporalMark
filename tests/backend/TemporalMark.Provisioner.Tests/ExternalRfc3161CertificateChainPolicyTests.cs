using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// Disposable, untrusted self-issued CA certificate only for existing
/// HTTP transport regressions. Never a production QTSP root.
/// </summary>
internal static class ExternalRfc3161TrustRootTestFixture
{
    private static readonly Lazy<string> LazyBase64 = new(() =>
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        return Convert.ToBase64String(root.RawData);
    });

    internal static string Base64Der => LazyBase64.Value;
}

/// <summary>
/// RED-first offline signer PKIX path tests: approved custom root ONLY;
/// no system CA fallback, CRL/OCSP/AIA fetch or legal qualification claim.
/// </summary>
public sealed class ExternalRfc3161CertificateChainPolicyTests
{
    private const string ExampleSha256Pin =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private const string ExamplePolicyOid = "1.3.6.1.4.1.4146.2.2";
    private static readonly Uri TsaUri = new("https://tsa.example.invalid/issue");

    [Fact]
    public void CanonicalDerRootCAIsImportedAndApproved()
    {
        using var root = CreateRoot();
        using var approved = ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(
            Convert.ToBase64String(root.RawData));

        Assert.Equal(root.RawData, approved.RawData);
        Assert.True(approved.Extensions.OfType<X509BasicConstraintsExtension>()
            .Single().CertificateAuthority);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("not-base64!")]
    [InlineData("MIIA")]
    [InlineData("AA==")]
    [InlineData("-----BEGIN CERTIFICATE-----")]
    public void MissingInvalidOrPemLikeTrustAnchorFailsClosed(string? bad)
    {
        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(bad));
    }

    [Fact]
    public void NoncanonicalOrMultipleBase64DERDataIsRejected()
    {
        using var root = CreateRoot();
        var proper = Convert.ToBase64String(root.RawData);

        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(proper + "\n"));
        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(" " + proper));
        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(proper + proper));
        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(
                Convert.ToBase64String([.. root.RawData, 0x00])));
        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(
                Convert.ToBase64String(new byte[70_000])));
    }

    [Fact]
    public void ALeafSignerCannotBeAnOperatorTrustAnchor()
    {
        using var root = CreateRoot();
        using var leaf = CreateSigner(root);

        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(
                Convert.ToBase64String(leaf.RawData)));
    }

    [Fact]
    public void RootMissingCertificateSigningKeyUsageIsRejected()
    {
        using var root = CreateRoot(keyCertSign: false);
        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(
                Convert.ToBase64String(root.RawData)));
    }

    [Fact]
    public void RootMissingCaBasicConstraintsIsRejected()
    {
        using var root = CreateRoot(isCa: false);
        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(
                Convert.ToBase64String(root.RawData)));
    }

    [Fact]
    public void IntermediateIsNotAcceptedAsAStandaloneRoot()
    {
        using var root = CreateRoot();
        using var intermediate = CreateIntermediate(root);
        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(
                Convert.ToBase64String(intermediate.RawData)));
    }

    [Fact]
    public void VerifiedSignerIssuedByReviewedRootPassesOfflinePath()
    {
        using var root = CreateRoot();
        using var leaf = CreateSigner(root);
        using var approved = ParseRoot(root);
        ExternalRfc3161CertificateChainPolicy.ValidateSignerChain(
            leaf, approved, new X509Certificate2Collection());
    }

    [Fact]
    public void DifferentOperatorRootCannotTrustSameSigner()
    {
        using var root = CreateRoot();
        using var wrongRoot = CreateRoot();
        using var leaf = CreateSigner(root);
        using var approved = ParseRoot(wrongRoot);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161CertificateChainPolicy.ValidateSignerChain(
                leaf, approved, new X509Certificate2Collection(root)));
    }

    [Fact]
    public void SelfSignedSignerIsNotAReviewedRoot()
    {
        using var root = CreateRoot();
        using var unapprovedSelfSigned = CreateRoot();
        using var approved = ParseRoot(root);
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161CertificateChainPolicy.ValidateSignerChain(
                unapprovedSelfSigned, approved, new X509Certificate2Collection()));
    }

    [Fact]
    public void ExpiredTsaLeafFailsCurrentTimePathCheck()
    {
        using var root = CreateRoot();
        using var expiredLeaf = CreateSigner(
            root, DateTimeOffset.UtcNow.AddDays(-15), DateTimeOffset.UtcNow.AddDays(-2));
        using var approved = ParseRoot(root);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161CertificateChainPolicy.ValidateSignerChain(
                expiredLeaf, approved, new X509Certificate2Collection()));
    }

    [Fact]
    public void IncludedCmsIntermediateBuildsFullApprovedPath()
    {
        using var root = CreateRoot();
        using var intermediate = CreateIntermediate(root);
        using var leaf = CreateSigner(intermediate);
        using var approved = ParseRoot(root);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161CertificateChainPolicy.ValidateSignerChain(
                leaf, approved, new X509Certificate2Collection()));

        ExternalRfc3161CertificateChainPolicy.ValidateSignerChain(
            leaf, approved, new X509Certificate2Collection(intermediate));
    }

    [Fact]
    public void LeafCertificateWithTamperedCaSignatureMustFailChain()
    {
        using var root = CreateRoot();
        using var leaf = CreateSigner(root);
        using var approved = ParseRoot(root);

        // Mutate the final byte of the DER signature BIT STRING while
        // retaining a parseable X.509 certificate. The issuing CA's
        // cryptographic signature must NOT be ignored by the path builder.
        var tamperedDer = leaf.RawData.ToArray();
        tamperedDer[^1] ^= 0x01;
        using var tampered = X509CertificateLoader.LoadCertificate(tamperedDer);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161CertificateChainPolicy.ValidateSignerChain(
                tampered, approved, new X509Certificate2Collection()));
    }

    [Fact]
    public void OfflineChainMustUseOnlyConfiguredRootAndNeverFetchAiaOrRevocation()
    {
        using var root = CreateRoot();
        using var approved = ParseRoot(root);
        using var chain = ExternalRfc3161CertificateChainPolicy.CreateOfflineChain(
            approved, new X509Certificate2Collection());

        Assert.Equal(X509ChainTrustMode.CustomRootTrust, chain.ChainPolicy.TrustMode);
        Assert.Single(chain.ChainPolicy.CustomTrustStore);
        Assert.Equal(root.RawData, chain.ChainPolicy.CustomTrustStore[0].RawData);
        Assert.Empty(chain.ChainPolicy.ExtraStore);
        Assert.True(chain.ChainPolicy.DisableCertificateDownloads);
        Assert.Equal(X509RevocationMode.NoCheck, chain.ChainPolicy.RevocationMode);
        Assert.Equal(X509VerificationFlags.NoFlag, chain.ChainPolicy.VerificationFlags);
    }

    [Fact]
    public void NullSignerOrEmptyPresentedCertificatesCannotBypassTrustCheck()
    {
        using var root = CreateRoot();
        using var approved = ParseRoot(root);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161CertificateChainPolicy.ValidateSignerChain(
                null, approved, new X509Certificate2Collection()));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("AABB")]
    public async Task InvalidOrAbsentApprovedRootFailsBeforeAnyHttpPost(string? base64)
    {
        using var capture = new CaptureHandler();
        using var http = new HttpClient(capture);
        var provider = new ExternalRfc3161TimestampProvider(
            http, TsaUri, "operator-approved-tsa",
            approvedSignerCertificateSha256: ExampleSha256Pin,
            approvedPolicyOid: ExamplePolicyOid,
            approvedTrustAnchorCertificateBase64Der: base64);

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, capture.Sends);
    }

    [Fact]
    public async Task ValidApprovedRootRetainsPriorHttpErrorBehavior()
    {
        using var capture = new CaptureHandler();
        using var http = new HttpClient(capture);
        var provider = new ExternalRfc3161TimestampProvider(
            http, TsaUri, "operator-approved-tsa",
            approvedSignerCertificateSha256: ExampleSha256Pin,
            approvedPolicyOid: ExamplePolicyOid,
            approvedTrustAnchorCertificateBase64Der: ExternalRfc3161TrustRootTestFixture.Base64Der);

        await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(1, capture.Sends);
    }

    [Fact]
    public async Task DisabledTsaStillNeedsNoApprovedRoot()
    {
        using var capture = new CaptureHandler();
        using var http = new HttpClient(capture);
        var provider = new ExternalRfc3161TimestampProvider(http, null, "disabled");

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, capture.Sends);
    }

    internal static X509Certificate2 CreateRoot(bool keyCertSign = true, bool isCa = true)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=Disposable RFC3161 local test root",
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            keyCertSign ? X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign
                        : X509KeyUsageFlags.DigitalSignature,
            critical: true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30),
            DateTimeOffset.UtcNow.AddDays(30));
    }

    private static X509Certificate2 CreateIntermediate(X509Certificate2 root)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=Disposable RFC3161 intermediate",
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        using var signed = req.Create(root, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(7), Serial());
        return signed.CopyWithPrivateKey(key);
    }

    private static X509Certificate2 CreateSigner(
        X509Certificate2 issuer,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Disposable RFC3161 TSA signer",
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature, true));
        var eku = new OidCollection { new Oid("1.3.6.1.5.5.7.3.8") };
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        using var issued = req.Create(issuer,
            notBefore ?? DateTimeOffset.UtcNow.AddHours(-1),
            notAfter ?? DateTimeOffset.UtcNow.AddDays(3), Serial());
        return issued.CopyWithPrivateKey(key);
    }

    private static byte[] Serial()
    {
        var bytes = RandomNumberGenerator.GetBytes(16);
        bytes[0] &= 0x7f;
        if (bytes[0] == 0)
            bytes[0] = 1;
        return bytes;
    }

    private static X509Certificate2 ParseRoot(X509Certificate2 root) =>
        ExternalRfc3161CertificateChainPolicy.ParseRequiredAnchorBase64Der(
            Convert.ToBase64String(root.RawData));

    private sealed class CaptureHandler : HttpMessageHandler
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
