using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using TemporalMark.Business.Tenancy;

namespace TemporalMark.Provisioner;

/// <summary>
/// Validates short-lived OIDC access tokens against a pinned issuer and signed
/// JWKS metadata. Never chooses a discovery URL based on untrusted JWT claims.
/// </summary>
public sealed class OidcAccessTokenVerifier : IVerifiedOidcTokenSource
{
    private readonly string issuer;
    private readonly IConfigurationManager<OpenIdConnectConfiguration> manager;

    public OidcAccessTokenVerifier(
        string expectedIssuer, bool permitLocalDevelopmentHttp,
        IConfigurationManager<OpenIdConnectConfiguration>? configuration = null)
    {
        if (!Uri.TryCreate(expectedIssuer, UriKind.Absolute, out var uri) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            (uri.Scheme != Uri.UriSchemeHttps &&
             !(permitLocalDevelopmentHttp && uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)))
            throw new ArgumentException("Issuer must use HTTPS, except explicitly allowed loopback development.", nameof(expectedIssuer));
        issuer = expectedIssuer.TrimEnd('/');
        manager = configuration ?? new ConfigurationManager<OpenIdConnectConfiguration>(
            issuer + "/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever { RequireHttps = uri.Scheme == Uri.UriSchemeHttps });
    }

    public async Task<VerifiedOidcToken> VerifyAsync(
        string accessToken, string expectedAudience, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(expectedAudience) || expectedAudience.Length > 255 ||
            string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > 16384)
            throw new UnauthorizedAccessException("Invalid verification inputs.");

        var config = await manager.GetConfigurationAsync(ct);
        if (config.Issuer != issuer || config.SigningKeys.Count == 0)
            throw new UnauthorizedAccessException("OIDC metadata failed pinned issuer/key checks.");

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = expectedAudience,
            ValidateLifetime = true,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = config.SigningKeys,
            ClockSkew = TimeSpan.FromSeconds(30),
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256,
                SecurityAlgorithms.RsaSsaPssSha256, SecurityAlgorithms.EcdsaSha256]
        };

        var validation = await new JsonWebTokenHandler().ValidateTokenAsync(accessToken, parameters);
        if (!validation.IsValid)
            throw new UnauthorizedAccessException("Access token signature, issuer, audience or lifetime invalid.");

        // Parse only AFTER successful cryptographic verification.
        var verifiedToken = new JsonWebToken(accessToken);
        using var payload = JsonDocument.Parse(Base64UrlEncoder.Decode(verifiedToken.EncodedPayload));
        var root = payload.RootElement;
        var sub = ClaimText(root, "sub");
        var issuedAt = ClaimLong(root, "iat");
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (string.IsNullOrWhiteSpace(sub) || sub.Length > 255 || sub != sub.Trim() ||
            sub.Any(char.IsControl) || issuedAt is null ||
            issuedAt.Value > now + 30 || issuedAt.Value < now - 300)
            throw new UnauthorizedAccessException("Token lacks a recent, trustworthy user identity.");

        // Refuse explicit ID-token claims or non-Bearer token types when declared.
        var type = ClaimText(root, "typ");
        if (type is not null && type != "Bearer" && type != "at+jwt")
            throw new UnauthorizedAccessException("An OIDC access token is required.");

        var roles = new HashSet<string>(StringComparer.Ordinal);
        ReadRoles(root, "role", roles);  // Keycloak mapped realm role
        ReadRoles(root, "roles", roles); // Entra app roles
        return new VerifiedOidcToken(issuer, sub, roles.ToArray());
    }

    private static string? ClaimText(JsonElement root, string key) =>
        root.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() : null;

    private static long? ClaimLong(JsonElement root, string key) =>
        root.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.Number &&
        value.TryGetInt64(out var number) ? number : null;

    private static void ReadRoles(JsonElement root, string key, HashSet<string> roles)
    {
        if (!root.TryGetProperty(key, out var value)) return;
        if (value.ValueKind == JsonValueKind.String && value.GetString() is { } one)
            roles.Add(one);
        if (value.ValueKind != JsonValueKind.Array) return;
        foreach (var item in value.EnumerateArray())
            if (item.ValueKind == JsonValueKind.String && item.GetString() is { } role)
                roles.Add(role);
    }
}
