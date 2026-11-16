using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Minimal, pre-send endpoint URI policy for the server-configured external TSA.
/// Does not resolve DNS or enforce network egress / qualified service trust.
/// </summary>
public static class ExternalRfc3161EndpointPolicy
{
    public static void Validate(Uri endpoint, bool allowDevelopmentLoopback = false)
    {
        ArgumentNullException.ThrowIfNull(endpoint);

        if (!endpoint.IsAbsoluteUri ||
            !string.IsNullOrEmpty(endpoint.UserInfo) ||
            !string.IsNullOrEmpty(endpoint.Fragment))
            throw new TimestampProviderUnavailableException("External TSA endpoint URI is not permitted.");

        // Only an explicitly development-configured caller can reach a loopback
        // HTTP(S) TSA. This can never be inferred from the URI or a tenant.
        if (allowDevelopmentLoopback && endpoint.IsLoopback &&
            (endpoint.Scheme == Uri.UriSchemeHttps || endpoint.Scheme == Uri.UriSchemeHttp))
            return;

        // Production deliberately requires named HTTPS authorities. In particular,
        // a direct IPv4/IPv6 literal, localhost, or link-local metadata address
        // cannot be a configured TSA endpoint. DNS rebinding still needs egress controls.
        if (endpoint.Scheme != Uri.UriSchemeHttps ||
            endpoint.IsLoopback ||
            endpoint.HostNameType != UriHostNameType.Dns)
            throw new TimestampProviderUnavailableException("External TSA endpoint URI is not permitted.");
    }
}
