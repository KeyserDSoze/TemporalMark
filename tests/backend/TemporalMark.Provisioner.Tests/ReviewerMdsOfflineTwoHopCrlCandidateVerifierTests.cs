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
/// RED-first real root → intermediate → leaf X509 path and TWO independently
/// signed v2 DER CRLs. Test roots are generated at runtime and never trusted
/// for FIDO provenance, real credential enrollment, SQL or timestamp issuance.
/// </summary>
public sealed class ReviewerMdsOfflineTwoHopCrlCandidateVerifierTests
{
    [Fact]
    public void TwoCurrentRealIssuerSignedCrlsReturnOnlyUnapprovedDigests()
    {
        using var fixture = new TwoHopFixture();
        var leafCrl = fixture.LeafCrl();
        var intermediateCrl = fixture.IntermediateCrl();
        var result = fixture.Inspect(leafCrl, intermediateCrl);

        Assert.Equal("UNAPPROVED", result.ReviewStatus);
        Assert.Equal("TWO_HOP_CRL_ONLY_ROOT_UNTRUSTED", result.PolicyStage);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(leafCrl)), result.LeafCrlSha256);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(intermediateCrl)), result.IntermediateCrlSha256);
        Assert.DoesNotContain(typeof(ReviewerMdsTwoHopCrlCandidate).GetProperties(),
            p => p.Name.Contains("Trusted", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("Active", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("PublicKey", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("Certificate", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RevokedLeafOrRevokedIntermediateIsRejectedEvenWhenOtherCrlIsGood()
    {
        using var fixture = new TwoHopFixture();
        var leafCrl = fixture.LeafCrl();
        var intermediateCrl = fixture.IntermediateCrl();
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(fixture.LeafCrl(revokeLeaf: true), intermediateCrl));
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(leafCrl, fixture.IntermediateCrl(revokeIntermediate: true)));
    }

    [Fact]
    public void MissingReorderedOrTamperedHopCrlIsRejected()
    {
        using var fixture = new TwoHopFixture();
        var leafCrl = fixture.LeafCrl();
        var intermediateCrl = fixture.IntermediateCrl();
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(null, intermediateCrl));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(leafCrl, null));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(leafCrl, leafCrl));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(intermediateCrl, leafCrl));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect([], intermediateCrl));
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(new byte[1_048_577], intermediateCrl));
        var tampered = intermediateCrl.ToArray();
        tampered[^1] ^= 1;
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(leafCrl, tampered));
    }

    [Fact]
    public void ForgedCrlSignatureOrWrongPinnedRootIsRejected()
    {
        using var fixture = new TwoHopFixture();
        using var other = new TwoHopFixture();
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(fixture.LeafCrl(signWith: other.RootKey),
                fixture.IntermediateCrl()));
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(fixture.LeafCrl(),
                fixture.IntermediateCrl(signWith: other.IntermediateKey)));
        Assert.Throws<UnauthorizedAccessException>(() =>
            ReviewerMdsOfflineTwoHopCrlCandidateVerifier.Inspect(
                fixture.Leaf, fixture.Intermediate, other.Root,
                fixture.LeafCrl(), fixture.IntermediateCrl(), fixture.Now));
        Assert.Throws<UnauthorizedAccessException>(() =>
            ReviewerMdsOfflineTwoHopCrlCandidateVerifier.Inspect(
                fixture.Leaf, other.Intermediate, fixture.Root,
                fixture.LeafCrl(), fixture.IntermediateCrl(), fixture.Now));
    }

    [Fact]
    public void CertificateOrderMustDescribeExactThreeHopPath()
    {
        using var fixture = new TwoHopFixture();
        Assert.Throws<UnauthorizedAccessException>(() =>
            ReviewerMdsOfflineTwoHopCrlCandidateVerifier.Inspect(
                fixture.Leaf, fixture.Root, fixture.Root,
                fixture.LeafCrl(), fixture.IntermediateCrl(), fixture.Now));
        Assert.Throws<UnauthorizedAccessException>(() =>
            ReviewerMdsOfflineTwoHopCrlCandidateVerifier.Inspect(
                fixture.Intermediate, fixture.Leaf, fixture.Root,
                fixture.LeafCrl(), fixture.IntermediateCrl(), fixture.Now));
        Assert.Throws<UnauthorizedAccessException>(() =>
            ReviewerMdsOfflineTwoHopCrlCandidateVerifier.Inspect(
                null, fixture.Intermediate, fixture.Root,
                fixture.LeafCrl(), fixture.IntermediateCrl(), fixture.Now));
    }

    [Fact]
    public void MissingCrlSignOnEitherIssuingCaIsDenied()
    {
        using var weakIntermediate = new TwoHopFixture(intermediateCanSignCrl: false);
        Assert.Throws<UnauthorizedAccessException>(() =>
            weakIntermediate.Inspect(weakIntermediate.LeafCrl(), weakIntermediate.IntermediateCrl()));
        using var weakRoot = new TwoHopFixture(rootCanSignCrl: false);
        Assert.Throws<UnauthorizedAccessException>(() =>
            weakRoot.Inspect(weakRoot.LeafCrl(), weakRoot.IntermediateCrl()));
    }

    [Fact]
    public void BothCrlsMustBeCurrentFullDirectIssuerSignedAndUnambiguous()
    {
        using var fixture = new TwoHopFixture();
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(
            fixture.LeafCrl(nextUpdate: fixture.Now.AddDays(-1)), fixture.IntermediateCrl()));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(
            fixture.LeafCrl(), fixture.IntermediateCrl(
                thisUpdate: fixture.Now.AddMinutes(10))));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(
            fixture.LeafCrl(extension: "delta"), fixture.IntermediateCrl()));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(
            fixture.LeafCrl(), fixture.IntermediateCrl(extension: "unknown-critical")));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(
            fixture.LeafCrl(), fixture.IntermediateCrl(extension: "indirect")));
        Assert.Throws<UnauthorizedAccessException>(() => fixture.Inspect(
            fixture.LeafCrl(), fixture.IntermediateCrl(includeNextUpdate: false)));
    }

    [Fact]
    public void ExpiredCertificatesAndNonUtcClockAreDenied()
    {
        using var fixture = new TwoHopFixture();
        var leafCrl = fixture.LeafCrl();
        var intermediateCrl = fixture.IntermediateCrl();
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(leafCrl, intermediateCrl, now: fixture.Now.AddDays(35)));
        Assert.Throws<UnauthorizedAccessException>(() =>
            fixture.Inspect(leafCrl, intermediateCrl, now: fixture.Now.ToOffset(TimeSpan.FromHours(1))));
    }

    private sealed class TwoHopFixture : IDisposable
    {
        public DateTimeOffset Now { get; } = DateTimeOffset.UtcNow;
        public RSA RootKey { get; } = RSA.Create(2048);
        public RSA IntermediateKey { get; } = RSA.Create(2048);
        private readonly RSA leafKey = RSA.Create(2048);
        public X509Certificate2 Root { get; }
        public X509Certificate2 Intermediate { get; }
        public X509Certificate2 Leaf { get; }

        public TwoHopFixture(bool rootCanSignCrl = true, bool intermediateCanSignCrl = true)
        {
            var rootRequest = new CertificateRequest(
                "CN=TemporalMark Disposable Root, O=TemporalMark Tests, C=IT",
                RootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            AddCaExtensions(rootRequest, rootCanSignCrl);
            Root = rootRequest.CreateSelfSigned(Now.AddDays(-5), Now.AddDays(90));

            var intermediateRequest = new CertificateRequest(
                "CN=TemporalMark Disposable Intermediate, O=TemporalMark Tests, C=IT",
                IntermediateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            AddCaExtensions(intermediateRequest, intermediateCanSignCrl);
            using var intermediateWithoutKey = intermediateRequest.Create(
                Root, Now.AddDays(-4), Now.AddDays(30), RandomNumberGenerator.GetBytes(12));
            Intermediate = intermediateWithoutKey.CopyWithPrivateKey(IntermediateKey);

            var leafRequest = new CertificateRequest(
                "CN=TemporalMark Disposable MDS Signer, O=TemporalMark Tests, C=IT",
                leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            leafRequest.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, true));
            leafRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            Leaf = leafRequest.Create(Intermediate, Now.AddDays(-2),
                Now.AddDays(8), RandomNumberGenerator.GetBytes(12));
        }

        private static void AddCaExtensions(CertificateRequest request, bool canSignCrl)
        {
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign |
                    (canSignCrl ? X509KeyUsageFlags.CrlSign : 0), true));
            request.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        }

        public byte[] LeafCrl(bool revokeLeaf = false, bool includeNextUpdate = true,
            DateTimeOffset? thisUpdate = null, DateTimeOffset? nextUpdate = null,
            RSA? signWith = null, string? extension = null) =>
            BuildCrl(Intermediate, signWith ?? IntermediateKey,
                revokeLeaf ? Leaf : null, includeNextUpdate, thisUpdate, nextUpdate, extension);

        public byte[] IntermediateCrl(bool revokeIntermediate = false, bool includeNextUpdate = true,
            DateTimeOffset? thisUpdate = null, DateTimeOffset? nextUpdate = null,
            RSA? signWith = null, string? extension = null) =>
            BuildCrl(Root, signWith ?? RootKey,
                revokeIntermediate ? Intermediate : null, includeNextUpdate, thisUpdate, nextUpdate, extension);

        private byte[] BuildCrl(X509Certificate2 issuer, RSA signer,
            X509Certificate2? revoked, bool includeNextUpdate,
            DateTimeOffset? thisUpdate, DateTimeOffset? nextUpdate, string? extension)
        {
            var generator = new X509V2CrlGenerator();
            generator.SetIssuerDN(DotNetUtilities.FromX509Certificate(issuer).SubjectDN);
            generator.SetThisUpdate((thisUpdate ?? Now.AddMinutes(-2)).UtcDateTime);
            if (includeNextUpdate)
                generator.SetNextUpdate((nextUpdate ?? Now.AddDays(1)).UtcDateTime);
            if (revoked is not null)
                generator.AddCrlEntry(DotNetUtilities.FromX509Certificate(revoked).SerialNumber,
                    Now.AddMinutes(-1).UtcDateTime, 0);
            if (extension == "unknown-critical")
                generator.AddExtension(new DerObjectIdentifier("1.2.3.4.5.6.7"), true, DerInteger.ValueOf(1));
            if (extension == "delta")
                generator.AddExtension(X509Extensions.DeltaCrlIndicator, true,
                    new CrlNumber(Org.BouncyCastle.Math.BigInteger.One));
            if (extension == "indirect")
                generator.AddExtension(X509Extensions.IssuingDistributionPoint, true,
                    new IssuingDistributionPoint(null, false, false, null, true, false));
            var signingPair = DotNetUtilities.GetRsaKeyPair(signer);
            return generator.Generate(new Asn1SignatureFactory(
                "SHA256WITHRSA", signingPair.Private)).GetEncoded();
        }

        public ReviewerMdsTwoHopCrlCandidate Inspect(
            byte[]? leafCrl, byte[]? intermediateCrl, DateTimeOffset? now = null) =>
            ReviewerMdsOfflineTwoHopCrlCandidateVerifier.Inspect(
                Leaf, Intermediate, Root, leafCrl, intermediateCrl, now ?? Now);

        public void Dispose()
        {
            Leaf.Dispose();
            Intermediate.Dispose();
            Root.Dispose();
            leafKey.Dispose();
            IntermediateKey.Dispose();
            RootKey.Dispose();
        }
    }
}
