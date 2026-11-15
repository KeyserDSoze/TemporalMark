using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using TemporalMark.Business.Tenancy;

namespace TemporalMark.Provisioner;

/// <summary>
/// Keycloak RFC 7662 live introspection. Each CheckAsync makes a fresh POST,
/// with a dedicated confidential client. No cached identity or fallback.
/// </summary>
public sealed class KeycloakTokenIntrospector : ILiveOidcTokenStatus, IDisposable
{
    private readonly Uri endpoint;
    private readonly HttpClient client;
    private readonly AuthenticationHeaderValue authentication;

    public KeycloakTokenIntrospector(
        string expectedIssuer, bool allowLocalHttp, string clientId, string clientSecret,
        HttpMessageHandler? transport = null)
    {
        if (!Uri.TryCreate(expectedIssuer, UriKind.Absolute, out var issuer) ||
            !string.IsNullOrEmpty(issuer.UserInfo) || !string.IsNullOrEmpty(issuer.Query) ||
            !string.IsNullOrEmpty(issuer.Fragment) ||
            (issuer.Scheme != Uri.UriSchemeHttps &&
             !(allowLocalHttp && issuer.Scheme == Uri.UriSchemeHttp && issuer.IsLoopback)))
            throw new ArgumentException("Introspection issuer must be pinned HTTPS (or explicit local loopback).",
                nameof(expectedIssuer));
        if (string.IsNullOrWhiteSpace(clientId) || clientId.Length > 128 ||
            clientId.Any(c => char.IsControl(c) || c == ':') ||
            string.IsNullOrWhiteSpace(clientSecret) || clientSecret.Length > 2048 ||
            clientSecret.Any(char.IsControl))
            throw new ArgumentException("Dedicated confidential introspection credentials are required.");

        endpoint = new Uri(issuer.AbsoluteUri.TrimEnd('/') + "/protocol/openid-connect/token/introspect");
        var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes(clientId + ":" + clientSecret));
        authentication = new AuthenticationHeaderValue("Basic", basic);
        client = new HttpClient(transport ?? new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false
        }, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(6)
        };
    }

    public async Task<LiveOidcTokenState> CheckAsync(
        string accessToken, string expectedAudience, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > 16384 ||
            accessToken.Any(char.IsWhiteSpace) ||
            string.IsNullOrWhiteSpace(expectedAudience) || expectedAudience.Length > 255)
            throw new UnauthorizedAccessException("Invalid introspection request.");

        using var request = new HttpRequestMessage(HttpMethod.Post, endpoint);
        request.Headers.Authorization = authentication;
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
        request.Content = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("token", accessToken),
            new KeyValuePair<string, string>("token_type_hint", "access_token")
        ]);

        using var response = await client.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.StatusCode != HttpStatusCode.OK ||
            response.Content.Headers.ContentType?.MediaType != "application/json")
            throw new UnauthorizedAccessException("OIDC token introspection is unavailable.");

        // Reject oversized or malformed JSON; never include raw IdP responses in errors/logs.
        await response.Content.LoadIntoBufferAsync(16384, ct);
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        using var payload = await JsonDocument.ParseAsync(stream,
            new JsonDocumentOptions { MaxDepth = 12 }, ct);
        var root = payload.RootElement;
        if (root.ValueKind != JsonValueKind.Object ||
            !root.TryGetProperty("active", out var active) ||
            active.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new UnauthorizedAccessException("Invalid live OIDC status response.");
        if (active.ValueKind == JsonValueKind.False)
            return new LiveOidcTokenState(false, null, null, [], []);

        var roles = new HashSet<string>(StringComparer.Ordinal);
        AddClaimValues(root, "role", roles);
        AddClaimValues(root, "roles", roles);
        if (root.TryGetProperty("realm_access", out var realm) &&
            realm.ValueKind == JsonValueKind.Object)
            AddClaimValues(realm, "roles", roles);

        var audiences = new HashSet<string>(StringComparer.Ordinal);
        AddClaimValues(root, "aud", audiences);
        return new LiveOidcTokenState(true, ClaimText(root, "iss"), ClaimText(root, "sub"),
            audiences.ToArray(), roles.ToArray());
    }

    private static string? ClaimText(JsonElement root, string key) =>
        root.TryGetProperty(key, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() : null;

    private static void AddClaimValues(JsonElement root, string key, HashSet<string> output)
    {
        if (!root.TryGetProperty(key, out var value)) return;
        if (value.ValueKind == JsonValueKind.String && value.GetString() is { } single)
            output.Add(single);
        else if (value.ValueKind == JsonValueKind.Array)
            foreach (var element in value.EnumerateArray())
                if (element.ValueKind == JsonValueKind.String && element.GetString() is { } item)
                    output.Add(item);
    }

    public void Dispose() => client.Dispose();
}
