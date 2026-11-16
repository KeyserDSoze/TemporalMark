using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Direct outbound transport for the configured RFC 3161 TSA. The callback
/// vets DNS answers and connects to exactly one of the vetted IP addresses,
/// never resolving the host a second time. Not a QTSP trust or egress firewall.
/// </summary>
public static class ExternalRfc3161TransportPolicy
{
    public static SocketsHttpHandler CreateHandler(bool allowDevelopmentLoopback = false) => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        // Do not inherit HTTPS_PROXY/ALL_PROXY or the operating system proxy.
        UseProxy = false,
        // A reused socket bypasses ConnectCallback until the pool replaces it.
        // One-minute lease bounds idle connection age (not in-flight requests).
        PooledConnectionLifetime = TimeSpan.FromSeconds(60),
        // Deliberate TSA-only TLS floor; keep platform chain/hostname/SNI
        // validation intact by not setting a certificate validation callback.
        SslOptions = new SslClientAuthenticationOptions
        {
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
        },
        // Connections must not bypass a public-address check via native DNS
        // after policy preflight. TLS/SNI is handled by SocketsHttpHandler.
        ConnectCallback = (context, ct) => ConnectValidatedAsync(
            context, allowDevelopmentLoopback, ct)
    };

    private static async ValueTask<Stream> ConnectValidatedAsync(
        SocketsHttpConnectionContext context,
        bool allowDevelopmentLoopback,
        CancellationToken cancellationToken)
    {
        var uri = context.InitialRequestMessage.RequestUri;
        var destination = context.DnsEndPoint;
        if (uri is null ||
            uri.Port != destination.Port ||
            (!string.Equals(uri.Host, destination.Host, StringComparison.OrdinalIgnoreCase) &&
             !string.Equals(uri.IdnHost, destination.Host, StringComparison.OrdinalIgnoreCase)))
            throw new HttpRequestException("TSA connection authority does not match its request.");

        try
        {
            ExternalRfc3161EndpointPolicy.Validate(uri, allowDevelopmentLoopback);
        }
        catch (TimestampProviderUnavailableException)
        {
            throw new HttpRequestException("TSA connection endpoint is not permitted.");
        }

        // Resolve once, check ALL returned answers, then connect by exact IP.
        // No DNS re-resolution between validation and socket connection.
        var addresses = await Dns.GetHostAddressesAsync(destination.Host, cancellationToken);
        ExternalRfc3161ResolvedDestinationPolicy.ValidateResolvedAddresses(
            uri, addresses, allowDevelopmentLoopback);

        SocketException? lastConnectionError = null;
        foreach (var address in addresses)
        {
            Socket? socket = null;
            try
            {
                socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
                await socket.ConnectAsync(address, destination.Port, cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex)
            {
                lastConnectionError = ex;
                socket?.Dispose();
            }
            catch
            {
                socket?.Dispose();
                throw;
            }
        }

        throw new HttpRequestException("Unable to connect to the approved TSA address.",
            lastConnectionError);
    }
}
