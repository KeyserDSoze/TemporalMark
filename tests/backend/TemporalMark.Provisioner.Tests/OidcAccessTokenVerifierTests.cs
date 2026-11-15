using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using TemporalMark.Provisioner;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

public sealed class OidcAccessTokenVerifierTests : IDisposable
{
    private const string Issuer = "https://oidc.example.test/realm";
    private const string Audience = "temporalmark-api";
    private readonly RSA rsa = RSA.Create(2048);
    private readonly RsaSecurityKey key;

    public OidcAccessTokenVerifierTests()
    {
        key = new RsaSecurityKey(rsa) { KeyId = "test-key" };
    }

    private OidcAccessTokenVerifier MakeVerifier(string metadataIssuer = Issuer)
    {
        var configuration = new OpenIdConnectConfiguration { Issuer = metadataIssuer };
        configuration.SigningKeys.Add(key);
        return new OidcAccessTokenVerifier(Issuer, false, new FixedConfiguration(configuration));
    }

    private string Sign(string issuer = Issuer, string audience = Audience, string subject = "approved-admin",
        string role = "tenant_admin", DateTime? issuedAt = null, DateTime? expires = null, bool unsigned = false)
    {
        var iat = issuedAt ?? DateTime.UtcNow.AddSeconds(-5);
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            IssuedAt = iat,
            NotBefore = iat,
            Expires = expires ?? DateTime.UtcNow.AddMinutes(4),
            Subject = new ClaimsIdentity([new Claim("sub", subject), new Claim("role", role),
                new Claim("typ", "Bearer")]),
            SigningCredentials = unsigned ? null : new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        };
        return new JsonWebTokenHandler().CreateToken(descriptor);
    }

    [Fact]
    public async Task AcceptsFreshSignedOidcAccessTokenWithExpectedAudience()
    {
        var identity = await MakeVerifier().VerifyAsync(Sign(), Audience, default);
        Assert.Equal(Issuer, identity.Issuer);
        Assert.Equal("approved-admin", identity.Subject);
        Assert.Contains("tenant_admin", identity.Roles);
    }

    [Theory]
    [InlineData("wrong-issuer")]
    [InlineData("wrong-audience")]
    [InlineData("expired")]
    [InlineData("stale")]
    [InlineData("unsigned")]
    [InlineData("tampered")]
    public async Task RejectsBadTokenAndDoesNotTrustUnvalidatedClaims(string failure)
    {
        var token = failure switch
        {
            "wrong-issuer" => Sign(issuer: "https://imposter.example.test"),
            "wrong-audience" => Sign(audience: "other-api"),
            "expired" => Sign(issuedAt: DateTime.UtcNow.AddHours(-1),
                expires: DateTime.UtcNow.AddMinutes(-1)),
            "stale" => Sign(issuedAt: DateTime.UtcNow.AddMinutes(-20)),
            "unsigned" => Sign(unsigned: true),
            _ => Sign()
        };
        if (failure == "tampered")
        {
            var signature = token.LastIndexOf('.');
            var changed = token[signature + 1] == 'A' ? 'B' : 'A';
            token = token[..(signature + 1)] + changed + token[(signature + 2)..];
        }
        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => MakeVerifier().VerifyAsync(token, Audience, default));
    }

    [Fact]
    public async Task RejectsMetadataThatNamesDifferentIssuer()
    {
        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => MakeVerifier("https://untrusted.example.test").VerifyAsync(Sign(), Audience, default));
    }

    [Fact]
    public void RefusesUnencryptedRemoteIssuerEvenIfInjectedConfigurationIsTrusted()
    {
        Assert.Throws<ArgumentException>(
            () => new OidcAccessTokenVerifier("http://oidc.example.test/realm", true));
    }

    [Fact]
    public void PermitsLoopbackHttpOnlyUnderExplicitDeveloperOptIn()
    {
        Assert.Throws<ArgumentException>(
            () => new OidcAccessTokenVerifier("http://localhost:8081/realms/temporalmark", false));
        var verifier = new OidcAccessTokenVerifier("http://localhost:8081/realms/temporalmark", true);
        Assert.NotNull(verifier);
    }

    public void Dispose() => rsa.Dispose();

    private sealed class FixedConfiguration(OpenIdConnectConfiguration config)
        : IConfigurationManager<OpenIdConnectConfiguration>
    {
        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken cancellationToken) =>
            Task.FromResult(config);
        public void RequestRefresh() { }
    }
}
