using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first real DER/X509 v2 CRL fixture with ephemeral test-only keys.
/// Successful CRL signature verification is not production FIDO root trust.
/// </summary>
public sealed class ReviewerMdsOfflineCrlCandidateVerifierTests
{
    [Fact]
    public void RealUnrevokedFreshSignedCrlReturnsOnlyUnapprovedDigest()
    {
        using var fixture = new CrlFixture();
        var crl = fixture.CreateCrl();
        var result = ReviewerMdsOfflineCrlCandidateVerifier.Inspect(
            fixture.Leaf, fixture.Root, crl, fixture.Now);
        Assert.Equal("UNAPPROVED", result.ReviewStatus);
        Assert.Equal("CRL_SIGNATURE_CHECK_ONLY_ROOT_UNTRUSTED", result.PolicyStage);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(crl)), result.CrlSha256);
        Assert.DoesNotContain(typeof(ReviewerMdsCrlCryptographicCandidate).GetProperties(),
            prop => prop.Name.Contains("Trusted", StringComparison.OrdinalIgnoreCase) ||
                prop.Name.Contains("ApprovedSigner", StringComparison.OrdinalIgnoreCase) ||
                prop.Name.Contains("PublicKey", StringComparison.OrdinalIgnoreCase) ||
                prop.Name.Contains("RawCertificate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RevokedLeafIsDeniedEvenWithValidCrlSignature()
    {
        using var fixture = new CrlFixture();
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(fixture.CreateCrl(revoked: true)));
    }

    [Fact]
    public void WrongSignerKeyOrUnrelatedIssuerCannotIssueAcceptableCrl()
    {
        using var fixture = new CrlFixture();
        using var other = new CrlFixture();
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(fixture.CreateCrl(overrideSigningKey: other.IssuerKey)));
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(other.CreateCrl()));
        Assert.Throws<UnauthorizedAccessException>(() =>
            ReviewerMdsOfflineCrlCandidateVerifier.Inspect(
                other.Leaf, fixture.Root, fixture.CreateCrl(), fixture.Now));
    }

    [Fact]
    public void CrlMustNotBeMissingTamperedMalformedOrConcatenated()
    {
        using var fixture = new CrlFixture();
        var crl = fixture.CreateCrl();
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(null));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect([]));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect([0x30, 0x01, 0x00]));
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(new byte[1_048_577]));
        var corrupted = crl.ToArray();
        corrupted[^1] ^= 1;
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(corrupted));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect([.. crl, 0x00]));
    }

    [Fact]
    public void NoExpiredFutureOrExcessivelyLongCrlValidityIsAllowed()
    {
        using var fixture = new CrlFixture();
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(fixture.CreateCrl(includeNextUpdate: false)));
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(fixture.CreateCrl(thisUpdate: fixture.Now.AddDays(-2),
                nextUpdate: fixture.Now.AddMinutes(-1))));
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(fixture.CreateCrl(thisUpdate: fixture.Now.AddMinutes(1),
                nextUpdate: fixture.Now.AddDays(2))));
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(fixture.CreateCrl(thisUpdate: fixture.Now.AddMinutes(-1),
                nextUpdate: fixture.Now.AddDays(40))));
    }

    [Fact]
    public void UnknownCriticalDeltaOrIndirectCrlExtensionIsDenied()
    {
        using var fixture = new CrlFixture();
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(fixture.CreateCrl(extension: "unknown-critical")));
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(fixture.CreateCrl(extension: "delta")));
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(fixture.CreateCrl(extension: "indirect")));
    }

    [Fact]
    public void IssuerMustBeRealCaWithCrlSignPermissionAndBothCertificatesCurrent()
    {
        using var insufficient = new CrlFixture(issuerCanSignCrl: false);
        Assert.Throws<UnauthorizedAccessException>(() =>
            insufficient.Inspect(insufficient.CreateCrl()));

        using var expiredLeaf = new CrlFixture(leafExpired: true);
        Assert.Throws<UnauthorizedAccessException>(() =>
            expiredLeaf.Inspect(expiredLeaf.CreateCrl()));

        using var fixture = new CrlFixture();
        Assert.Throws<UnauthorizedAccessException>(() =>
            ReviewerMdsOfflineCrlCandidateVerifier.Inspect(fixture.Leaf,
                fixture.Root, fixture.CreateCrl(), fixture.Now.AddDays(40)));
    }

    private sealed class CrlFixture : IDisposable
    {
        public DateTimeOffset Now { get; } = DateTimeOffset.UtcNow;
        public RSA IssuerKey { get; } = RSA.Create(2048);
        private readonly RSA leafKey = RSA.Create(2048);
        public X509Certificate2 Root { get; }
        public X509Certificate2 Leaf { get; }

        public CrlFixture(bool issuerCanSignCrl = true, bool leafExpired = false)
        {
            var ca = new CertificateRequest(
                "CN=TemporalMark Temporary CRL CA, O=TemporalMark Tests, C=IT",
                IssuerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            ca.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));
            ca.CertificateExtensions.Add(
                new X509KeyUsageExtension(
                    X509KeyUsageFlags.KeyCertSign |
                    (issuerCanSignCrl ? X509KeyUsageFlags.CrlSign : 0), true));
            Root = ca.CreateSelfSigned(Now.AddDays(-4), Now.AddDays(90));

            var leafReq = new CertificateRequest(
                "CN=TemporalMark Disposable CRL Leaf, O=TemporalMark Tests, C=IT",
                leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            leafReq.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, true));
            leafReq.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            var before = leafExpired ? Now.AddDays(-3) : Now.AddDays(-1);
            var after = leafExpired ? Now.AddMinutes(-1) : Now.AddDays(5);
            Leaf = leafReq.Create(Root, before, after, RandomNumberGenerator.GetBytes(12));
        }

        public byte[] CreateCrl(bool revoked = false, bool includeNextUpdate = true,
            DateTimeOffset? thisUpdate = null, DateTimeOffset? nextUpdate = null,
            RSA? overrideSigningKey = null, string? extension = null)
        {
            var gen = new X509V2CrlGenerator();
            gen.SetIssuerDN(DotNetUtilities.FromX509Certificate(Root).SubjectDN);
            gen.SetThisUpdate((thisUpdate ?? Now.AddMinutes(-2)).UtcDateTime);
            if (includeNextUpdate)
                gen.SetNextUpdate((nextUpdate ?? Now.AddDays(1)).UtcDateTime);
            if (revoked)
                gen.AddCrlEntry(DotNetUtilities.FromX509Certificate(Leaf).SerialNumber,
                    Now.AddMinutes(-1).UtcDateTime, 0);
            if (extension == "unknown-critical")
                gen.AddExtension(new DerObjectIdentifier("1.2.3.4.5.6.7"), true, DerInteger.ValueOf(1));
            if (extension == "delta")
                gen.AddExtension(X509Extensions.DeltaCrlIndicator, true, new CrlNumber(Org.BouncyCastle.Math.BigInteger.One));
            if (extension == "indirect")
                gen.AddExtension(X509Extensions.IssuingDistributionPoint, true,
                    new IssuingDistributionPoint(null, false, false, null, true, false));
            var keyPair = DotNetUtilities.GetRsaKeyPair(overrideSigningKey ?? IssuerKey);
            return gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", keyPair.Private)).GetEncoded();
        }

        public ReviewerMdsCrlCryptographicCandidate Inspect(byte[]? crl) =>
            ReviewerMdsOfflineCrlCandidateVerifier.Inspect(Leaf, Root, crl, Now);

        public void Dispose()
        {
            Leaf.Dispose();
            Root.Dispose();
            leafKey.Dispose();
            IssuerKey.Dispose();
        }
    }
}
