using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace TemporalMark.Infrastructure.Postgres;

/// <summary>
/// #131 / ADR 0097: detached, strictly local Azure Container Apps managed
/// identity token supplier for the #130 Entra Npgsql candidate. Available only
/// via explicit nondefault #134 API Entra opt-in; not selected by current
/// Terraform or wired to provisioning CLI / SQL migration runner.
/// </summary>
public sealed class ContainerAppsPostgresManagedIdentityCandidate : IDisposable
{
    private const string Scope = EntraPostgresDataSourceCandidate.PostgreSqlEntraScope;
    private const string Resource = "https://ossrdbms-aad.database.windows.net";
    private const string Failure = "Azure Container Apps PostgreSQL managed identity token unavailable";
    private const int MaxResponseBytes = 32768;
    private const int MaxTokenLength = 16000;
    // #139 / ADR 0104: one deadline for response headers AND complete body.
    private static readonly TimeSpan TokenResponseDeadline = TimeSpan.FromSeconds(10);

    private readonly HttpClient client;
    private readonly Uri endpoint;
    private readonly string platformIdentityHeader;
    private readonly Guid approvedUserAssignedClientId;
    private readonly TimeProvider clock;
    private readonly TimeSpan responseDeadline;

    private ContainerAppsPostgresManagedIdentityCandidate(
        HttpClient client, string endpointUrl, string identityHeader,
        Guid clientId, TimeProvider? timeProvider, TimeSpan responseDeadline)
    {
        if (responseDeadline <= TimeSpan.Zero || responseDeadline > TokenResponseDeadline)
            throw new ArgumentOutOfRangeException(nameof(responseDeadline),
                "A strictly bounded token response deadline is required");
        try
        {
            endpoint = new Uri(endpointUrl, UriKind.Absolute);
        }
        catch (Exception)
        {
            // Bad URL may contain userinfo, fragments or fake credentials.
            throw new ArgumentException("Invalid local Container Apps identity endpoint", nameof(endpointUrl));
        }

        // The Azure Container Apps identity endpoint is an HTTP URL local to
        // the app, not the VM's 169.254.169.254 IMDS or an untrusted hostname.
        // This allows the documented localhost endpoint but denies arbitrary
        // hostnames and DNS rebinding via the pinned production transport.
        if (endpoint.Scheme != Uri.UriSchemeHttp ||
            !(endpoint.Host == "localhost" || endpoint.Host == "127.0.0.1" || endpoint.Host == "::1") ||
            endpoint.IsDefaultPort || endpoint.Port <= 0 ||
            endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 ||
            endpoint.Fragment.Length != 0 ||
            !Regex.IsMatch(endpoint.AbsolutePath, @"\A/[A-Za-z0-9/_-]{1,128}\z",
                RegexOptions.CultureInvariant))
            throw new ArgumentException("A strict local Container Apps identity endpoint is required", nameof(endpointUrl));

        // No implicit system-assigned identity. The approved Entra SQL identity
        // must be a separate, reviewed UAI; existing system MI handles Blob.
        if (clientId == Guid.Empty)
            throw new ArgumentException("An approved user-assigned managed identity client ID is required",
                nameof(clientId));

        // X-IDENTITY-HEADER is a rotated platform secret. Never log, serialize
        // or echo it in a URL or exception. Control chars/whitespace forbidden.
        if (string.IsNullOrEmpty(identityHeader) || identityHeader.Length > 512 ||
            identityHeader.Any(c => c < '!' || c > '~'))
            throw new ArgumentException("A valid platform identity request header is required",
                nameof(identityHeader));

        this.client = client;
        platformIdentityHeader = identityHeader;
        approvedUserAssignedClientId = clientId;
        clock = timeProvider ?? TimeProvider.System;
        this.responseDeadline = responseDeadline;
    }

    /// <summary>
    /// Construct with a hardened local-only transport. Does not fetch any
    /// token or connect to Azure until GetTokenAsync is explicitly called.
    /// </summary>
    public static ContainerAppsPostgresManagedIdentityCandidate Create(
        string endpointUrl, string identityHeader, Guid userAssignedClientId,
        TimeProvider? timeProvider = null)
    {
        var client = new HttpClient(CreateHardenedHandler(), disposeHandler: true)
        {
            Timeout = TokenResponseDeadline
        };
        try
        {
            return new ContainerAppsPostgresManagedIdentityCandidate(
                client, endpointUrl, identityHeader, userAssignedClientId,
                timeProvider, TokenResponseDeadline);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Strictly in-memory mocked transport for the existing Provisioner.Tests
    /// assembly. Never used by an API handler or deployed Azure path.
    /// </summary>
    internal static ContainerAppsPostgresManagedIdentityCandidate CreateForTests(
        HttpMessageHandler handler, string endpointUrl, string identityHeader,
        Guid userAssignedClientId, TimeProvider? timeProvider = null,
        TimeSpan? testResponseDeadline = null)
    {
        ArgumentNullException.ThrowIfNull(handler);
        var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TokenResponseDeadline
        };
        try
        {
            return new ContainerAppsPostgresManagedIdentityCandidate(
                client, endpointUrl, identityHeader, userAssignedClientId,
                timeProvider, testResponseDeadline ?? TokenResponseDeadline);
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Hardened outgoing HTTP: no ambient proxy, HTTP redirects, cookies,
    /// automatic compression or DNS-based remote resolution. Connect to the
    /// literal loopback address even if local hosts/DNS are compromised.
    /// Only the constructor's validated loopback URI can be used by this client.
    /// </summary>
    internal static SocketsHttpHandler CreateHardenedHandler() => new()
    {
        UseProxy = false,
        Proxy = null,
        AllowAutoRedirect = false,
        UseCookies = false,
        AutomaticDecompression = DecompressionMethods.None,
        Credentials = null,
        PreAuthenticate = false,
        ConnectTimeout = TimeSpan.FromSeconds(3),
        MaxConnectionsPerServer = 2,
        PooledConnectionLifetime = TimeSpan.FromMinutes(2),
        ConnectCallback = async (context, cancellationToken) =>
        {
            var address = context.DnsEndPoint.Host == "::1"
                ? IPAddress.IPv6Loopback
                : IPAddress.Loopback;
            if (context.DnsEndPoint.Host is not ("localhost" or "127.0.0.1" or "::1"))
                throw new InvalidOperationException(Failure);

            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await socket.ConnectAsync(address, context.DnsEndPoint.Port, cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }
    };

    /// <summary>
    /// Callback for EntraPostgresDataSourceCandidate.Create. The incoming
    /// OAuth scope and outgoing ACA REST resource are deliberately distinct.
    /// No caching, retries, disk access, SQL fallback or ambient credentials.
    /// </summary>
    public async ValueTask<string> GetTokenAsync(string scope, CancellationToken cancellationToken)
    {
        if (!string.Equals(scope, Scope, StringComparison.Ordinal))
            throw new ArgumentException("An approved PostgreSQL managed identity scope is required",
                nameof(scope));
        cancellationToken.ThrowIfCancellationRequested();

        // The HttpClient.Timeout above covers only headers under ResponseHeadersRead.
        // One monotonic linked cancellation budget covers headers + streaming body;
        // it is never reset per read. External cancellation retains its own identity.
        using var requestBudget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        requestBudget.CancelAfter(responseDeadline);
        try
        {
            var uri = new UriBuilder(endpoint)
            {
                Query = "resource=" + Uri.EscapeDataString(Resource) +
                        "&api-version=2019-08-01&client_id=" +
                        approvedUserAssignedClientId.ToString("D", CultureInfo.InvariantCulture)
            }.Uri;
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Add("X-IDENTITY-HEADER", platformIdentityHeader);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Version = HttpVersion.Version11;
            request.VersionPolicy = HttpVersionPolicy.RequestVersionExact;

            using var response = await client.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, requestBudget.Token);
            if (response.StatusCode != HttpStatusCode.OK ||
                response.Content is null ||
                response.Content.Headers.ContentLength > MaxResponseBytes ||
                response.Content.Headers.ContentType?.MediaType != "application/json")
                throw new InvalidOperationException(Failure);

            var bytes = await ReadBoundedResponseAsync(response.Content, requestBudget.Token);
            using var document = JsonDocument.Parse(bytes);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !HasUniqueTopLevelPropertyNames(root) ||
                ReadString(root, "resource") != Resource ||
                ReadString(root, "token_type") != "Bearer" ||
                !Guid.TryParse(ReadString(root, "client_id"), out var responseClientId) ||
                responseClientId != approvedUserAssignedClientId)
                throw new InvalidOperationException(Failure);

            var token = ReadString(root, "access_token");
            if (string.IsNullOrEmpty(token) || token.Length > MaxTokenLength ||
                token.Any(c => c < '!' || c > '~'))
                throw new InvalidOperationException(Failure);

            if (!TryReadExpiry(root, out var expiresOnSeconds))
                throw new InvalidOperationException(Failure);
            var expires = DateTimeOffset.FromUnixTimeSeconds(expiresOnSeconds);
            var now = clock.GetUtcNow();
            if (expires < now.AddMinutes(2) || expires > now.AddHours(24))
                throw new InvalidOperationException(Failure);

            return token;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // Never attach exception or inner exception: the identity endpoint
            // could echo header/bearer into JSON, HTTP or transport errors.
            throw new InvalidOperationException(Failure);
        }
    }

    // #138 / ADR 0103: JsonElement.TryGetProperty chooses the last value
    // when a JSON object repeats a name. Deny ambiguous credential payloads
    // before reading any field, including case-variant aliases, without
    // printing or preserving untrusted names or token values in exceptions.
    private static bool HasUniqueTopLevelPropertyNames(JsonElement root)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var property in root.EnumerateObject())
        {
            if (!seen.Add(property.Name))
                return false;
        }
        return true;
    }

    private static string? ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static bool TryReadExpiry(JsonElement root, out long result)
    {
        result = 0;
        if (!root.TryGetProperty("expires_on", out var value))
            return false;
        return value.ValueKind switch
        {
            JsonValueKind.String => long.TryParse(
                value.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out result),
            JsonValueKind.Number => value.TryGetInt64(out result),
            _ => false
        };
    }

    private static async Task<byte[]> ReadBoundedResponseAsync(
        HttpContent content, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        while (true)
        {
            var count = await stream.ReadAsync(chunk, cancellationToken);
            if (count == 0)
                break;
            if (buffer.Length + count > MaxResponseBytes)
                throw new InvalidOperationException(Failure);
            buffer.Write(chunk, 0, count);
        }
        return buffer.ToArray();
    }

    public void Dispose() => client.Dispose();
}
