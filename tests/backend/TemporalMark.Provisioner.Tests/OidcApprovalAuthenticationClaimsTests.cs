using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using TemporalMark.Provisioner;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

public sealed class OidcApprovalAuthenticationClaimsTests : IDisposable
{
    private const string Issuer = "https://auth.example.test/realms/prod";
    private const string Audience = "temporalmark-approval";
    private readonly RSA rsa = RSA.Create(2048);
    private readonly RsaSecurityKey key;

    public OidcApprovalAuthenticationClaimsTests() => key = new RsaSecurityKey(rsa) { KeyId = "kid" };

    private OidcAccessTokenVerifier Verifier()
    {
        var metadata = new OpenIdConnectConfiguration { Issuer = Issuer };
        metadata.SigningKeys.Add(key);
        return new OidcAccessTokenVerifier(Issuer, false, new StaticConfiguration(metadata));
    }

    private string Sign(string? acr, long? authTime, bool unsigned = false)
    {
        var claims = new List<Claim> {
            new("sub", "reviewer-sub"), new("role", "platform_approver"), new("typ", "Bearer")
        };
        if (acr is not null) claims.Add(new Claim("acr", acr));
        if (authTime is not null)
            claims.Add(new Claim("auth_time", authTime.Value.ToString(),
                ClaimValueTypes.Integer64));
        var iat = DateTime.UtcNow.AddSeconds(-10);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer, Audience = Audience,
            IssuedAt = iat, NotBefore = iat, Expires = DateTime.UtcNow.AddMinutes(2),
            Subject = new ClaimsIdentity(claims),
            SigningCredentials = unsigned ? null :
                new SigningCredentials(key, SecurityAlgorithms.RsaSha256)
        });
    }

    [Fact]
    public async Task ReturnsAuthenticationEvidenceOnlyFromVerifiedJwt()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var token = Sign("urn:temporalmark:loa:2", now - 25);
        var verified = await Verifier().VerifyAsync(token, Audience, default);
        Assert.Equal("urn:temporalmark:loa:2", verified.AuthenticationContext);
        Assert.Equal(now - 25, verified.AuthenticationTimeUnix);
        Assert.NotNull(verified.IssuedAtUnix);
    }

    [Fact]
    public async Task MissingAuthenticationContextOrTimeAreNotFabricated()
    {
        var verified = await Verifier().VerifyAsync(Sign(null, null), Audience, default);
        Assert.Null(verified.AuthenticationContext);
        Assert.Null(verified.AuthenticationTimeUnix);
    }

    [Fact]
    public async Task ForgedClaimInUnsignedTokenCannotBeReadAsTrustedAuthentication()
    {
        var forged = Sign("urn:temporalmark:loa:2", DateTimeOffset.UtcNow.ToUnixTimeSeconds(), unsigned: true);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => Verifier().VerifyAsync(forged, Audience, default));
    }

    [Fact]
    public async Task TamperedSignedTokenCannotBeTrustedEvenWithMatchingAcr()
    {
        var original = Sign("urn:temporalmark:loa:2", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        var end = original.LastIndexOf('.');
        var other = original[end + 1] == 'A' ? 'B' : 'A';
        var tampered = original[..(end + 1)] + other + original[(end + 2)..];
        await Assert.ThrowsAsync<UnauthorizedAccessException>(
            () => Verifier().VerifyAsync(tampered, Audience, default));
    }

    public void Dispose() => rsa.Dispose();

    private sealed class StaticConfiguration(OpenIdConnectConfiguration metadata)
        : IConfigurationManager<OpenIdConnectConfiguration>
    {
        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken ct) =>
            Task.FromResult(metadata);
        public void RequestRefresh() { }
    }
}
