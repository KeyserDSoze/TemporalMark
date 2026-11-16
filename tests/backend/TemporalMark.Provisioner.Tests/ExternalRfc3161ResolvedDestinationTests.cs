using System.Net;
using System.Net.Sockets;
using System.Text;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first RFC3161 connection-bound DNS/IP guard regressions.
/// Public IP syntax is NOT QTSP ownership, TLS assurance or legal qualification.
/// </summary>
public sealed class ExternalRfc3161ResolvedDestinationTests
{
    [Theory]
    [InlineData("0.0.0.0")]
    [InlineData("10.10.1.2")]
    [InlineData("100.64.1.1")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("172.16.0.1")]
    [InlineData("172.31.255.254")]
    [InlineData("192.0.0.1")]
    [InlineData("192.0.2.42")]
    [InlineData("192.168.1.3")]
    [InlineData("198.18.0.1")]
    [InlineData("198.51.100.5")]
    [InlineData("203.0.113.42")]
    [InlineData("224.0.0.1")]
    [InlineData("240.0.0.1")]
    [InlineData("255.255.255.255")]
    [InlineData("::")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("::ffff:8.8.8.8")]
    [InlineData("fe80::1")]
    [InlineData("fd12:3456::1")]
    [InlineData("ff02::1")]
    [InlineData("2001:db8::12")]
    [InlineData("2002:c0a8:0101::1")]
    public void ReservedOrNonPublicAddressesAreNotEligible(string ip)
    {
        Assert.False(ExternalRfc3161ResolvedDestinationPolicy.IsEligiblePublicAddress(IPAddress.Parse(ip)));
    }

    [Theory]
    [InlineData("1.1.1.1")]
    [InlineData("8.8.8.8")]
    [InlineData("9.9.9.9")]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("2606:4700:4700::1111")]
    public void PublicUnicastAddressCanBeAnEligibleTsaConnectionTarget(string ip)
    {
        Assert.True(ExternalRfc3161ResolvedDestinationPolicy.IsEligiblePublicAddress(IPAddress.Parse(ip)));
    }

    [Fact]
    public void EmptyDnsResponseFailsClosedBeforeAnyDial()
    {
        Assert.Throws<HttpRequestException>(() =>
            ExternalRfc3161ResolvedDestinationPolicy.ValidateResolvedAddresses(
                new Uri("https://tsa.example.invalid/issue"), Array.Empty<IPAddress>()));
    }

    [Theory]
    [InlineData("10.0.0.10")]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("::ffff:169.254.169.254")]
    [InlineData("fc00::10")]
    public void MixedPublicAndForbiddenDnsAnswersDenyEntireResponse(string badIp)
    {
        Assert.Throws<HttpRequestException>(() =>
            ExternalRfc3161ResolvedDestinationPolicy.ValidateResolvedAddresses(
                new Uri("https://tsa.example.invalid/issue"),
                new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse(badIp) }));
    }

    [Fact]
    public void MultiplePublicDnsAnswersPassTogether()
    {
        ExternalRfc3161ResolvedDestinationPolicy.ValidateResolvedAddresses(
            new Uri("https://tsa.example.invalid/issue"),
            new[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("2001:4860:4860::8888") });
    }

    [Theory]
    [InlineData("http://127.0.0.1:8123/tsr")]
    [InlineData("https://localhost:8123/tsr")]
    public void DevLoopbackRequiresExplicitOptInAndAllResolvedIPsLoopback(string uri)
    {
        var endpoint = new Uri(uri);
        var loopback = new[] { IPAddress.Loopback, IPAddress.IPv6Loopback };

        Assert.Throws<HttpRequestException>(() =>
            ExternalRfc3161ResolvedDestinationPolicy.ValidateResolvedAddresses(endpoint, loopback));

        ExternalRfc3161ResolvedDestinationPolicy.ValidateResolvedAddresses(
            endpoint, loopback, allowDevelopmentLoopback: true);
    }

    [Fact]
    public void DevelopmentLoopbackDnsAnswerMayNeverContainPrivateNonLoopback()
    {
        Assert.Throws<HttpRequestException>(() =>
            ExternalRfc3161ResolvedDestinationPolicy.ValidateResolvedAddresses(
                new Uri("http://localhost:8123/issue"),
                new[] { IPAddress.Loopback, IPAddress.Parse("10.0.0.2") },
                allowDevelopmentLoopback: true));
    }

    [Fact]
    public void DevelopmentModeDoesNotPermitPrivateAnswersForPublicDnsName()
    {
        Assert.Throws<HttpRequestException>(() =>
            ExternalRfc3161ResolvedDestinationPolicy.ValidateResolvedAddresses(
                new Uri("https://tsa.example.invalid/issue"),
                new[] { IPAddress.Parse("10.0.0.2") },
                allowDevelopmentLoopback: true));
    }

    [Fact]
    public void DedicatedTsaHandlerHasConnectionTimeHookAndPreservesHttpPolicy()
    {
        using var handler = ExternalRfc3161TransportPolicy.CreateHandler();

        Assert.NotNull(handler.ConnectCallback);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.False(handler.UseProxy);
        Assert.Null(handler.Credentials);
        Assert.Null(handler.DefaultProxyCredentials);
        Assert.Null(handler.Proxy);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
    }

    [Fact]
    public async Task DefaultHandlerRefusesLocalTcpConnectionEvenWithoutProviderUriCheck()
    {
        using var handler = ExternalRfc3161TransportPolicy.CreateHandler();
        using var http = new HttpClient(handler);
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            http.GetAsync("http://127.0.0.1:8123/issue", cts.Token));
    }

    [Fact]
    public async Task ExplicitDevelopmentHandlerUsesActualTcpConnectionToLoopback()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var handler = ExternalRfc3161TransportPolicy.CreateHandler(allowDevelopmentLoopback: true);
            using var http = new HttpClient(handler);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

            var responseTask = http.GetAsync($"http://127.0.0.1:{port}/local", cts.Token);
            using var accepted = await listener.AcceptTcpClientAsync(cts.Token);
            await using var stream = accepted.GetStream();

            var buffer = new byte[2048];
            var n = await stream.ReadAsync(buffer, cts.Token);
            Assert.Contains("GET /local", Encoding.ASCII.GetString(buffer, 0, n), StringComparison.Ordinal);

            await stream.WriteAsync(
                "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(), cts.Token);
            using var reply = await responseTask;
            Assert.Equal(HttpStatusCode.NoContent, reply.StatusCode);
        }
        finally
        {
            listener.Stop();
        }
    }
}
