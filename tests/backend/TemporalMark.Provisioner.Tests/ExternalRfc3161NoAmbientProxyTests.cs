using System.Net;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first policy regression: no ambient system/HTTPS_PROXY forward-proxy
/// routing for the RFC 3161 TSA client. Does not prove actual network egress.
/// </summary>
public sealed class ExternalRfc3161NoAmbientProxyTests
{
    [Fact]
    public void DedicatedTsaHttpHandlerFailsClosedOnAmbientProxyRouting()
    {
        using var handler = ExternalRfc3161TransportPolicy.CreateHandler();

        Assert.False(handler.UseProxy);
        Assert.Null(handler.Proxy);
        Assert.Null(handler.DefaultProxyCredentials);
        Assert.False(handler.UseDefaultCredentials);
        Assert.Null(handler.Credentials);
        Assert.False(handler.PreAuthenticate);
    }

    [Fact]
    public void DedicatedTsaHttpHandlerPreservesExistingRedirectCookieAndCompressionGuards()
    {
        using var handler = ExternalRfc3161TransportPolicy.CreateHandler();

        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
    }

    [Fact]
    public void EachDedicatedHandlerIsIndependentAndHasSameProxyPolicy()
    {
        using var first = ExternalRfc3161TransportPolicy.CreateHandler();
        using var second = ExternalRfc3161TransportPolicy.CreateHandler();

        Assert.NotSame(first, second);
        Assert.False(first.UseProxy);
        Assert.False(second.UseProxy);
        Assert.False(first.AllowAutoRedirect);
        Assert.False(second.AllowAutoRedirect);
    }
}
