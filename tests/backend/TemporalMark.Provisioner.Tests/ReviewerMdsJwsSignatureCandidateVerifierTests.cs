using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first signature/chain test with disposable test-only RSA CA and leaf.
/// It does not establish FIDO Alliance R46 trust or CRL revocation proof.
/// </summary>
public sealed class ReviewerMdsJwsSignatureCandidateVerifierTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 16, 0, 0, 0, TimeSpan.Zero);

    private static Task<ReviewerMdsJwsCryptographicCandidate> CheckAsync(
        SignedBlobFixture fixture, string? jwt = null,
        X509Certificate2? root = null,
        DateTimeOffset? now = null) =>
        ReviewerMdsJwsSignatureCandidateVerifier.InspectAsync(
            jwt ?? fixture.Token(), root ?? fixture.Root, now ?? Now);

    [Fact]
    public async Task RealRsaSignedPinnedRootChainReturnsOnlyUnapprovedDigestAndSerial()
    {
        using var fixture = new SignedBlobFixture(Now);
        var token = fixture.Token();
        var result = await CheckAsync(fixture, token);
        Assert.Equal("UNAPPROVED", result.ReviewStatus);
        Assert.Equal("JWS_CHAIN_ONLY_REVOCATION_UNVERIFIED", result.PolicyStage);
        Assert.Equal(42, result.MetadataSerial);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token))),
            result.SignedBlobSha256);
        Assert.Equal(64, result.SignedBlobSha256.Length);
        Assert.DoesNotContain(typeof(ReviewerMdsJwsCryptographicCandidate).GetProperties(),
            p => p.Name.Contains("Trusted", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Certificate", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("PublicKey", StringComparison.OrdinalIgnoreCase) ||
                p.Name.Contains("Active", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task PayloadOrSignatureTamperingDeniesByRealJwtSignatureVerification()
    {
        using var fixture = new SignedBlobFixture(Now);
        var parts = fixture.Token().Split('.');
        parts[1] = SignedBlobFixture.Base64Url(Encoding.UTF8.GetBytes(
            "{\"no\":43,\"entries\":[],\"nextUpdate\":\"2026-11-18\"}"));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, string.Join(".", parts)));

        parts = fixture.Token().Split('.');
        var signature = SignedBlobFixture.FromBase64Url(parts[2]);
        signature[0] ^= 0x01;
        parts[2] = SignedBlobFixture.Base64Url(signature);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, string.Join(".", parts)));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("HS256")]
    [InlineData("ES256")]
    [InlineData("RS512")]
    public async Task AlgorithmConfusionOrUnsupportedAlgorithmIsRejected(string alg)
    {
        using var fixture = new SignedBlobFixture(Now);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(alg: alg)));
    }

    [Fact]
    public async Task UnpinnedSignerWrongSigningKeyOrInjectedExtraX5cAreDenied()
    {
        using var fixture = new SignedBlobFixture(Now);
        using var other = new SignedBlobFixture(Now);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, root: other.Root));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(signingKey: other.LeafSigningKey)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(extraX5cCertificate: other.Root)));
    }

    [Theory]
    [InlineData("x5u")]
    [InlineData("jku")]
    [InlineData("jwk")]
    [InlineData("crit")]
    public async Task ForbiddenExternalOrUntrustedHeaderFieldsAreRejected(string field)
    {
        using var fixture = new SignedBlobFixture(Now);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(extraHeaderKey: field)));
    }

    [Fact]
    public async Task NoCertificateMalformedHeaderDuplicateHeaderOrNoncanonicalJwtDenied()
    {
        using var fixture = new SignedBlobFixture(Now);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(includeX5c: false)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(headerOverride: "{not-json")));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(headerOverride:
                "{\"alg\":\"RS256\",\"alg\":\"RS256\",\"typ\":\"JWT\",\"iat\":1}")));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token() + "="));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token() + ".extra"));
    }

    [Fact]
    public async Task LeafTimeConstraintsAreValidatedIndependentlyOfJwtSignature()
    {
        using var expired = new SignedBlobFixture(
            Now, Now.AddDays(-3), Now.AddHours(-2));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => CheckAsync(expired));
        using var future = new SignedBlobFixture(
            Now, Now.AddHours(1), Now.AddDays(2));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => CheckAsync(future));
    }

    [Fact]
    public async Task IatFreshnessAndSerialAreDeniedWithoutSignedCurrentScope()
    {
        using var fixture = new SignedBlobFixture(Now);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(iat: Now.AddHours(-25))));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(iat: Now.AddMinutes(1))));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(includeIat: false)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(serial: 0)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(serial: -3)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(serial: "42")));
    }

    [Fact]
    public async Task OversizedJwtAndUnboundedX5cCannotBeAccepted()
    {
        using var fixture = new SignedBlobFixture(Now);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, new string('A', 1_100_000)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            CheckAsync(fixture, fixture.Token(extraHeaderKey: new string('z', 70_000))));
    }

    private sealed class SignedBlobFixture : IDisposable
    {
        private readonly RSA rootKey = RSA.Create(2048);
        public RSA LeafSigningKey { get; } = RSA.Create(2048);
        public X509Certificate2 Root { get; }
        private readonly X509Certificate2 leaf;
        private readonly DateTimeOffset issuedAt;

        public SignedBlobFixture(DateTimeOffset now,
            DateTimeOffset? leafNotBefore = null, DateTimeOffset? leafNotAfter = null)
        {
            issuedAt = now.AddMinutes(-2);
            var issuer = new CertificateRequest(
                "CN=TemporalMark Test MDS Root, O=TemporalMark Fixture, C=IT",
                rootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            issuer.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(true, false, 0, true));
            issuer.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            Root = issuer.CreateSelfSigned(now.AddDays(-5), now.AddDays(30));

            var request = new CertificateRequest(
                "CN=TemporalMark Test MDS Leaf, O=TemporalMark Fixture, C=IT",
                LeafSigningKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(
                new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            using var certificateOnly = request.Create(Root,
                leafNotBefore ?? now.AddHours(-1),
                leafNotAfter ?? now.AddDays(2), RandomNumberGenerator.GetBytes(12));
            leaf = certificateOnly.CopyWithPrivateKey(LeafSigningKey);
        }

        public string Token(string alg = "RS256", string? extraHeaderKey = null,
            bool includeX5c = true, bool includeIat = true,
            DateTimeOffset? iat = null, object? serial = null,
            string? headerOverride = null, RSA? signingKey = null,
            X509Certificate2? extraX5cCertificate = null)
        {
            var header = new Dictionary<string, object>
            {
                ["alg"] = alg, ["typ"] = "JWT"
            };
            if (includeIat) header["iat"] = (iat ?? issuedAt).ToUnixTimeSeconds();
            if (includeX5c)
            {
                var certs = new List<string> { Convert.ToBase64String(leaf.RawData) };
                if (extraX5cCertificate is not null)
                    certs.Add(Convert.ToBase64String(extraX5cCertificate.RawData));
                header["x5c"] = certs;
            }
            if (extraHeaderKey is not null) header[extraHeaderKey] = "https://attacker.invalid/key";

            var payload = new Dictionary<string, object>
            {
                ["legalHeader"] = "TemporalMark ephemeral test-only BLOB",
                ["no"] = serial ?? 42,
                ["nextUpdate"] = "2026-11-18",
                ["entries"] = Array.Empty<object>()
            };
            var encodedHeader = Base64Url(Encoding.UTF8.GetBytes(
                headerOverride ?? JsonSerializer.Serialize(header)));
            var encodedPayload = Base64Url(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload)));
            var toSign = encodedHeader + "." + encodedPayload;
            var signature = (signingKey ?? LeafSigningKey).SignData(
                Encoding.ASCII.GetBytes(toSign), HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
            return toSign + "." + Base64Url(signature);
        }

        public static string Base64Url(byte[] bytes) =>
            Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        public static byte[] FromBase64Url(string text) =>
            Convert.FromBase64String(text.Replace('-', '+').Replace('_', '/') +
                new string('=', (4 - text.Length % 4) % 4));

        public void Dispose()
        {
            leaf.Dispose();
            Root.Dispose();
            LeafSigningKey.Dispose();
            rootKey.Dispose();
        }
    }
}
