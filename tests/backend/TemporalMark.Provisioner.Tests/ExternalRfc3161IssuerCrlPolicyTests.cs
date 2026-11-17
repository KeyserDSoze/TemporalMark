using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first: independently signed RFC5280 CRL, not a claim of
/// historical QTSP service qualification or all-hop revocation.
/// All CA keys and CRLs are disposable local test fixtures.
/// </summary>
public sealed class ExternalRfc3161IssuerCrlPolicyTests
{
    private const string DummySignerSha256 =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    private static readonly Uri TsaUrl = new("https://tsa.example.invalid/issue");

    [Fact]
    public void ValidCompleteRootSignedCrlWithoutLeafRevocationIsAccepted()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var leaf = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var when = DateTimeOffset.UtcNow;
        var crl = BuildCrl(root, when);

        ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
            leaf, root, crl, when);
    }

    [Fact]
    public void IssuerSignedCrlListingTsaSignerMustFailClosed()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var leaf = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var when = DateTimeOffset.UtcNow;
        var builder = new CertificateRevocationListBuilder();
        builder.AddEntry(leaf, revocationTime: when.AddMinutes(-30));
        var revoked = BuildCrl(root, when, builder);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
                leaf, root, revoked, when));
    }

    [Fact]
    public void AnyListedSerialIsConservativelyRejectedEvenWithLaterRevocationDate()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var leaf = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var when = DateTimeOffset.UtcNow;
        var builder = new CertificateRevocationListBuilder();
        builder.AddEntry(leaf, revocationTime: when.AddMinutes(5));
        var crl = BuildCrl(root, when, builder);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
                leaf, root, crl, when));
    }

    [Fact]
    public void SignedCrlForDifferentRootWithSameDnMustNotBeTrusted()
    {
        using var reviewedRoot = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var attackerRoot = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var signer = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(reviewedRoot);
        var now = DateTimeOffset.UtcNow;
        var crl = BuildCrl(attackerRoot, now);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
                signer, reviewedRoot, crl, now));
    }

    [Fact]
    public void TamperedSignedCrlMustFailVerification()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var leaf = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var when = DateTimeOffset.UtcNow;
        var crl = BuildCrl(root, when);
        crl[^1] ^= 0x01;

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
                leaf, root, crl, when));
    }

    [Fact]
    public void NotYetEffectiveCrlMustFailAtSignedGenTime()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var leaf = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var when = DateTimeOffset.UtcNow;
        var crl = BuildCrl(root, when, thisUpdate: when.AddHours(1),
            nextUpdate: when.AddDays(1));

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
                leaf, root, crl, when));
    }

    [Fact]
    public void StaleCrlMustFailAtSignedGenTime()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var leaf = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var when = DateTimeOffset.UtcNow;
        var crl = BuildCrl(root, when, thisUpdate: when.AddDays(-3),
            nextUpdate: when.AddDays(-1));

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
                leaf, root, crl, when));
    }

    [Fact]
    public void CrlForLeafIssuedByIntermediateMustFailRatherThanSkipRevocation()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var intermediate = ExternalRfc3161CertificateChainPolicyTests.CreateIntermediate(root);
        using var leaf = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(intermediate);
        var when = DateTimeOffset.UtcNow;
        var rootCrl = BuildCrl(root, when);

        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
                leaf, root, rootCrl, when));
    }

    [Fact]
    public void CrlWithTrailingDerOrCorruptedHeaderMustFail()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var leaf = ExternalRfc3161CertificateChainPolicyTests.CreateSigner(root);
        var when = DateTimeOffset.UtcNow;
        var crl = BuildCrl(root, when);

        byte[] trailingDer = [.. crl, 0x00];
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
                leaf, root, trailingDer, when));
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ValidateDirectIssuerLeaf(
                leaf, root, new byte[] { 0x05, 0x00 }, when));
    }

    [Fact]
    public void CanonicalSingleBase64DerCrlCanBePreflightParsed()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        var bytes = BuildCrl(root, DateTimeOffset.UtcNow);
        var imported = ExternalRfc3161IssuerCrlPolicy.ParseRequiredCrlBase64Der(
            Convert.ToBase64String(bytes));

        Assert.Equal(bytes, imported);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("not-a-crl")]
    [InlineData("AA==")]
    [InlineData("-----BEGIN X509 CRL-----")]
    public void MissingInvalidOrNonDerCrlCannotEnableTsa(string? raw)
    {
        Assert.Throws<TimestampProviderUnavailableException>(() =>
            ExternalRfc3161IssuerCrlPolicy.ParseRequiredCrlBase64Der(raw));
    }

    [Fact]
    public void NoncanonicalTrailingAndOversizedCrlAreRejectedAtPreflight()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        var der = BuildCrl(root, DateTimeOffset.UtcNow);
        var good = Convert.ToBase64String(der);

        foreach (var bad in new[]
        {
            good + "\n",
            " " + good,
            good + good,
            Convert.ToBase64String([.. der, 0x00]),
            Convert.ToBase64String(new byte[1_050_000])
        })
        {
            Assert.Throws<TimestampProviderUnavailableException>(() =>
                ExternalRfc3161IssuerCrlPolicy.ParseRequiredCrlBase64Der(bad));
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("BADCRL")]
    public async Task MissingCrlWithConfiguredTsaCannotSendHttp(string? crl)
    {
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var provider = new ExternalRfc3161TimestampProvider(
            http, TsaUrl, "reviewed",
            approvedSignerCertificateSha256: DummySignerSha256,
            approvedPolicyOid: "1.3.6.1.4.1.4146.2.2",
            approvedTrustAnchorCertificateBase64Der: ExternalRfc3161TrustRootTestFixture.Base64Der,
            approvedIssuerCrlBase64Der: crl,
            approvedRootCrlNumberFloor: "1");

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, handler.Sends);
    }

    [Fact]
    public async Task ValidCrlAllowsExistingEnvelopeFailureToReachHttp()
    {
        using var root = ExternalRfc3161CertificateChainPolicyTests.CreateRoot();
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var provider = new ExternalRfc3161TimestampProvider(
            http, TsaUrl, "reviewed",
            approvedSignerCertificateSha256: DummySignerSha256,
            approvedPolicyOid: "1.3.6.1.4.1.4146.2.2",
            approvedTrustAnchorCertificateBase64Der: Convert.ToBase64String(root.RawData),
            approvedIssuerCrlBase64Der: Convert.ToBase64String(BuildCrl(root, DateTimeOffset.UtcNow)),
            approvedRootCrlNumberFloor: "1");

        await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(1, handler.Sends);
    }

    [Fact]
    public async Task DisabledTsaNeedsNoCrl()
    {
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var provider = new ExternalRfc3161TimestampProvider(http, null, "disabled");

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, handler.Sends);
    }

    internal static byte[] BuildCrl(
        X509Certificate2 issuer,
        DateTimeOffset when,
        CertificateRevocationListBuilder? builder = null,
        DateTimeOffset? thisUpdate = null,
        DateTimeOffset? nextUpdate = null,
        BigInteger? crlNumber = null)
    {
        return (builder ?? new CertificateRevocationListBuilder()).Build(
            issuer, crlNumber ?? BigInteger.One,
            nextUpdate ?? when.AddDays(1),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1,
            thisUpdate ?? when.AddMinutes(-10));
    }

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
