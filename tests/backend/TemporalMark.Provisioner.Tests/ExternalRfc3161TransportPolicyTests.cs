using System.Net;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first: a TSA relocation may never silently forward a hash imprint to
/// a different origin. This is transport hardening, not QTSP trust validation.
/// </summary>
public sealed class ExternalRfc3161TransportPolicyTests
{
    [Fact]
    public void DedicatedPrimaryHandlerDoesNotFollowRedirectsOrRetainCookies()
    {
        using var handler = ExternalRfc3161TransportPolicy.CreateHandler();

        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
    }

    [Theory]
    [InlineData(HttpStatusCode.MovedPermanently)]
    [InlineData(HttpStatusCode.Redirect)]
    [InlineData(HttpStatusCode.SeeOther)]
    [InlineData(HttpStatusCode.TemporaryRedirect)]
    [InlineData(HttpStatusCode.PermanentRedirect)]
    public async Task AllRedirectResponsesFailClosedWithoutProducingAReceipt(HttpStatusCode status)
    {
        using var redirect = new RedirectingTestHandler(status);
        using var http = new HttpClient(redirect);
        var tsa = new ExternalRfc3161TimestampProvider(
            http, new Uri("https://example.invalid/pinned-tsa"), "configured-tsa");

        await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            tsa.RequestAsync(new byte[32], CancellationToken.None));

        Assert.Equal(1, redirect.RequestCount);
        Assert.Equal("https://example.invalid/pinned-tsa", redirect.RequestUri?.AbsoluteUri);
    }

    private sealed class RedirectingTestHandler(HttpStatusCode redirectCode) : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public Uri? RequestUri { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            RequestUri = request.RequestUri;
            return Task.FromResult(new HttpResponseMessage(redirectCode)
            {
                Headers = { Location = new Uri("https://other.example.invalid/leak") }
            });
        }
    }
}
