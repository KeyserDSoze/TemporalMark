using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using TemporalMark.Business.Tenancy;

namespace TemporalMark.Provisioner;

/// <summary>
/// Fresh, independent Keycloak Admin REST account/realm-role checks.
/// NEVER derived from an access token's stale role claims.
/// Dedicated service account must only have realm-management read privileges.
/// </summary>
public sealed class KeycloakCurrentAccountDirectory : ICurrentOidcAccountDirectory, IDisposable
{
    private readonly string issuer;
    private readonly Uri tokenEndpoint;
    private readonly Uri adminBase;
    private readonly AuthenticationHeaderValue clientAuthentication;
    private readonly HttpClient http;

    public KeycloakCurrentAccountDirectory(
        string expectedIssuer, bool allowLocalHttp, string clientId, string clientSecret,
        HttpMessageHandler? transport = null)
    {
        if (!Uri.TryCreate(expectedIssuer, UriKind.Absolute, out var u) ||
            !string.IsNullOrEmpty(u.UserInfo) || !string.IsNullOrEmpty(u.Query) ||
            !string.IsNullOrEmpty(u.Fragment) ||
            (u.Scheme != Uri.UriSchemeHttps &&
             !(allowLocalHttp && u.Scheme == Uri.UriSchemeHttp && u.IsLoopback)))
            throw new ArgumentException("A pinned HTTPS issuer is required (explicit local loopback only).",
                nameof(expectedIssuer));

        // Only a pinned, unambiguous Keycloak realm URL is accepted. Never
        // construct Admin REST paths using an unvalidated JWT's issuer.
        var path = u.AbsolutePath;
        var prefix = "/realms/";
        var at = path.LastIndexOf(prefix, StringComparison.Ordinal);
        if (at < 0 || at + prefix.Length >= path.Length)
            throw new ArgumentException("Issuer must identify a Keycloak realm.", nameof(expectedIssuer));
        var realm = path[(at + prefix.Length)..];
        if (realm.Length is < 1 or > 100 ||
            !realm.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'))
            throw new ArgumentException("Unsafe Keycloak realm name.", nameof(expectedIssuer));

        if (string.IsNullOrWhiteSpace(clientId) || clientId.Length > 128 ||
            clientId.Contains(':') || clientId.Any(char.IsControl) ||
            string.IsNullOrWhiteSpace(clientSecret) || clientSecret.Length > 2048 ||
            clientSecret.Any(char.IsControl))
            throw new ArgumentException("A dedicated confidential directory client is mandatory.");

        issuer = expectedIssuer.TrimEnd('/');
        tokenEndpoint = new Uri(issuer + "/protocol/openid-connect/token");
        var contextPath = path[..at];
        adminBase = new Uri(u.GetLeftPart(UriPartial.Authority) + contextPath +
            "/admin/realms/" + realm + "/");
        clientAuthentication = new AuthenticationHeaderValue("Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes(clientId + ":" + clientSecret)));
        http = new HttpClient(transport ?? new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false
        }, disposeHandler: true)
        {
            Timeout = TimeSpan.FromSeconds(8)
        };
    }

    public async Task<CurrentOidcAccount> GetAccountAsync(
        string expectedIssuer, string subject, CancellationToken ct)
    {
        if (expectedIssuer != issuer || !Guid.TryParse(subject, out var id) ||
            id == Guid.Empty || subject.Length > 64)
            throw new UnauthorizedAccessException("Untrusted Keycloak subject or issuer.");

        // Fetch a fresh (not cached) dedicated service-account token for EVERY
        // lookup; errors are not interpreted as permission to proceed.
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post, tokenEndpoint);
        tokenRequest.Headers.Authorization = clientAuthentication;
        tokenRequest.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
        tokenRequest.Content = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("grant_type", "client_credentials")
        ]);
        using var serviceTokenJson = await FetchJsonAsync(tokenRequest, ct);
        var token = GetString(serviceTokenJson.RootElement, "access_token");
        if (string.IsNullOrWhiteSpace(token) || token.Length > 16384 ||
            token.Any(char.IsWhiteSpace))
            throw new UnauthorizedAccessException("No valid directory service credential.");

        using var userRequest = AdminGet("users/" + id.ToString("D"), token);
        using var userDocument = await FetchJsonAsync(userRequest, ct);
        var user = userDocument.RootElement;
        if (user.ValueKind != JsonValueKind.Object ||
            !Guid.TryParse(GetString(user, "id"), out var found) || found != id ||
            !user.TryGetProperty("enabled", out var enabled) ||
            enabled.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new UnauthorizedAccessException("Directory account identity malformed.");
        if (enabled.ValueKind != JsonValueKind.True)
            return new CurrentOidcAccount(issuer, subject, false, []);

        using var rolesRequest = AdminGet(
            "users/" + id.ToString("D") + "/role-mappings/realm/composite", token);
        using var rolesDocument = await FetchJsonAsync(rolesRequest, ct);
        if (rolesDocument.RootElement.ValueKind != JsonValueKind.Array)
            throw new UnauthorizedAccessException("Directory roles malformed.");

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var role in rolesDocument.RootElement.EnumerateArray())
        {
            if (role.ValueKind != JsonValueKind.Object ||
                GetString(role, "name") is not { Length: > 0 and <= 255 } name)
                throw new UnauthorizedAccessException("Invalid effective realm role.");
            names.Add(name);
        }
        return new CurrentOidcAccount(issuer, subject, true, names.ToArray());
    }

    private HttpRequestMessage AdminGet(string relativePath, string bearer)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, new Uri(adminBase, relativePath));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        request.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true, NoStore = true };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return request;
    }

    private async Task<JsonDocument> FetchJsonAsync(HttpRequestMessage request, CancellationToken ct)
    {
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        if (response.StatusCode != HttpStatusCode.OK ||
            response.Content.Headers.ContentType?.MediaType != "application/json")
            throw new UnauthorizedAccessException("Keycloak directory lookup unavailable.");
        await response.Content.LoadIntoBufferAsync(16384, ct);
        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        return await JsonDocument.ParseAsync(stream, new JsonDocumentOptions { MaxDepth = 12 }, ct);
    }

    private static string? GetString(JsonElement obj, string property) =>
        obj.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() : null;

    public void Dispose() => http.Dispose();
}
