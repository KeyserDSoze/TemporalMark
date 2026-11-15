namespace TemporalMark.Api;

/// <summary>
/// Local Docker only: route IdP discovery/JWKS over Docker DNS while keeping browser-visible
/// issuer/authority unchanged. Never enable this rewrite in non-development environments.
/// </summary>
internal sealed class DevelopmentAuthorityHandler : DelegatingHandler
{
    private readonly Uri _external;
    private readonly Uri _internal;

    public DevelopmentAuthorityHandler(string externalAuthority, string internalAuthority)
        : base(new HttpClientHandler())
    {
        _external = new Uri(externalAuthority.TrimEnd('/') + "/");
        _internal = new Uri(internalAuthority.TrimEnd('/') + "/");
    }

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        if (request.RequestUri is { } uri && uri.AbsoluteUri.StartsWith(_external.AbsoluteUri, StringComparison.Ordinal))
        {
            var suffix = uri.AbsoluteUri[_external.AbsoluteUri.Length..];
            request.RequestUri = new Uri(_internal, suffix);
        }
        return base.SendAsync(request, cancellationToken);
    }
}
