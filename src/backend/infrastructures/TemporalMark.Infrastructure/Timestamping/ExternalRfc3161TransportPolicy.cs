namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Dedicated outbound transport for the server-configured RFC 3161 TSA.
/// Redirects must never move the imprint-bearing POST to an unapproved origin.
/// This is not a certificate, egress-network or QTSP trust validation policy.
/// </summary>
public static class ExternalRfc3161TransportPolicy
{
    public static HttpClientHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        // Do not inherit HTTPS_PROXY, ALL_PROXY or OS forward proxies:
        // the timestamp imprint must use a reviewed direct TSA egress route.
        UseProxy = false
    };
}
