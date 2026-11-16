using System.Net;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first real provider / no-network spy-handler endpoint authority tests.
/// These prove only URL syntax and explicit dev-loopback gating, NOT DNS or QTSP trust.
/// </summary>
public sealed class ExternalRfc3161EndpointPolicyTests
{
    [Theory]
    [InlineData("http://localhost:8080/tsa")]
    [InlineData("http://127.0.0.1:8080/tsa")]
    [InlineData("https://localhost/tsa")]
    [InlineData("https://127.0.0.1/tsa")]
    [InlineData("https://169.254.169.254/latest/meta-data")]
    [InlineData("https://[::1]/tsa")]
    [InlineData("https://[::ffff:169.254.169.254]/tsa")]
    [InlineData("https://alice:secret@tsa.example.invalid/tsa")]
    [InlineData("https://tsa.example.invalid/tsa#ignored")]
    [InlineData("ftp://tsa.example.invalid/tsa")]
    [InlineData("http://tsa.example.invalid/tsa")]
    public async Task DefaultProductionPolicyRejectsUnsafeDestinationBeforeHttp(string url)
    {
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var provider = new ExternalRfc3161TimestampProvider(
            http, new Uri(url), "configured-provider",
            approvedSignerCertificateSha256: new string('A', 64));

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, handler.Sends);
    }

    [Theory]
    [InlineData("http://localhost:8111/tsa")]
    [InlineData("https://localhost:8111/tsa")]
    [InlineData("http://127.0.0.1:8111/tsa")]
    [InlineData("https://[::1]:8111/tsa")]
    public async Task ExplicitDevelopmentOnlyLoopbackAllowsTestingButNoQualifiedReceipt(string url)
    {
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var provider = new ExternalRfc3161TimestampProvider(
            http, new Uri(url), "disposable-test-provider", allowDevelopmentLoopback: true,
            approvedSignerCertificateSha256: new string('A', 64));

        await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(1, handler.Sends);
    }

    [Theory]
    [InlineData("http://tsa.example.invalid/tsa")]
    [InlineData("https://169.254.169.254/tsa")]
    [InlineData("https://alice:secret@tsa.example.invalid/tsa")]
    [InlineData("https://tsa.example.invalid/tsa#ignored")]
    public async Task DevelopmentFlagCannotOverrideNonLoopbackOrUserInfoOrFragment(string url)
    {
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var provider = new ExternalRfc3161TimestampProvider(
            http, new Uri(url), "disposable-test-provider", allowDevelopmentLoopback: true,
            approvedSignerCertificateSha256: new string('A', 64));

        await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(0, handler.Sends);
    }

    [Theory]
    [InlineData("https://tsa.example.invalid/api/v1/issue")]
    [InlineData("https://tsa.example.invalid:443/issue?policy=1.2.3")]
    public async Task NamedHttpsTsaRemainsReachableAndStillRequiresValidRfc3161Response(string url)
    {
        using var handler = new CountingHandler();
        using var http = new HttpClient(handler);
        var provider = new ExternalRfc3161TimestampProvider(
            http, new Uri(url), "configured-provider",
            approvedSignerCertificateSha256: new string('A', 64));

        await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(1, handler.Sends);
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        public int Sends { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sends++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadGateway)
            {
                Content = new ByteArrayContent(Array.Empty<byte>())
            });
        }
    }
}
