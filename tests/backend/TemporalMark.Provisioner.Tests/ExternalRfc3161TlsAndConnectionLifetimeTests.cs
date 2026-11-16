using System.Net;
using System.Security.Authentication;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first test of the actual dedicated TSA SocketsHttpHandler settings.
/// A finite pooled lifetime forces a new connection-time DNS check on refresh.
/// No TLS certificate trust or QTSP qualified status is implied.
/// </summary>
public sealed class ExternalRfc3161TlsAndConnectionLifetimeTests
{
    [Fact]
    public void DedicatedTsaConnectionsMustExpireFromPoolAfterOneMinute()
    {
        using var handler = ExternalRfc3161TransportPolicy.CreateHandler();

        Assert.Equal(TimeSpan.FromSeconds(60), handler.PooledConnectionLifetime);
        Assert.NotEqual(Timeout.InfiniteTimeSpan, handler.PooledConnectionLifetime);
        Assert.NotNull(handler.ConnectCallback); // existing #87 guarded socket dial
    }

    [Fact]
    public void DedicatedTsaTlsNegotiationAllowsOnlyTls12AndTls13()
    {
        using var handler = ExternalRfc3161TransportPolicy.CreateHandler();

        Assert.Equal(
            SslProtocols.Tls12 | SslProtocols.Tls13,
            handler.SslOptions.EnabledSslProtocols);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void DevelopmentLoopbackModeDoesNotWeakenPooledOrTlsPolicy(bool allowDevelopmentLoopback)
    {
        using var handler =
            ExternalRfc3161TransportPolicy.CreateHandler(allowDevelopmentLoopback);

        Assert.Equal(TimeSpan.FromSeconds(60), handler.PooledConnectionLifetime);
        Assert.Equal(
            SslProtocols.Tls12 | SslProtocols.Tls13,
            handler.SslOptions.EnabledSslProtocols);
        Assert.NotNull(handler.ConnectCallback);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.False(handler.UseProxy);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
    }

    [Fact]
    public void TsaTransportDoesNotOverrideNormalServerCertificateValidation()
    {
        using var handler = ExternalRfc3161TransportPolicy.CreateHandler();

        Assert.Null(handler.SslOptions.RemoteCertificateValidationCallback);
        Assert.Null(handler.Credentials);
        Assert.Null(handler.DefaultProxyCredentials);
        Assert.Null(handler.Proxy);
    }

    [Fact]
    public void FreshDedicatedHandlersHaveNoSharedTlsOrConnectionPoolState()
    {
        using var first = ExternalRfc3161TransportPolicy.CreateHandler();
        using var second = ExternalRfc3161TransportPolicy.CreateHandler();

        Assert.NotSame(first, second);
        Assert.NotSame(first.SslOptions, second.SslOptions);
        Assert.NotNull(first.ConnectCallback);
        Assert.NotNull(second.ConnectCallback);
    }
}
