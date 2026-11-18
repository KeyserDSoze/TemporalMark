using System.Net;
using System.Net.Http.Headers;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first RFC 3161 §3.4 HTTP envelope checks. A valid HTTP envelope
/// does not authenticate the external TSA or qualify a timestamp.
/// </summary>
public sealed class ExternalRfc3161ResponseEnvelopeTests
{
    [Theory]
    [InlineData(HttpStatusCode.Created)]
    [InlineData(HttpStatusCode.Accepted)]
    [InlineData(HttpStatusCode.NoContent)]
    [InlineData(HttpStatusCode.PartialContent)]
    public async Task NonOkSuccessStatusIsDeniedBeforeReadingBody(HttpStatusCode status)
    {
        using var content = new ReadDeniedContent("application/timestamp-reply");
        var error = await InvokeAsync(status, content);
        Assert.Contains("HTTP status", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(content.ReadAttempted);
    }

    [Theory]
    [InlineData(HttpStatusCode.RequestTimeout)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.GatewayTimeout)]
    public async Task UpstreamOverloadAndTimeoutAreSanitizedUnavailableBeforeBody(
        HttpStatusCode status)
    {
        // RED-first #104: upstream capacity/timeout headers are not malformed
        // RFC3161 tokens. No reading an untrusted body or automatic replay.
        using var content = new ReadDeniedContent("application/json");
        using var http = new HttpClient(new ReplyHandler(status, content,
            includeRetryAfter: true));
        var tsa = CreateProvider(http);

        var error = await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            tsa.RequestAsync(new byte[32], CancellationToken.None));

        Assert.Equal("External TSA is temporarily unavailable.", error.Message);
        Assert.DoesNotContain("99999", error.Message, StringComparison.Ordinal);
        Assert.False(content.ReadAttempted);
    }

    [Theory]
    [InlineData(HttpStatusCode.MovedPermanently)]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.BadGateway)]
    public async Task OtherNonOkHttpStatusesRemainInvalidResponseBeforeBody(
        HttpStatusCode status)
    {
        using var content = new ReadDeniedContent("application/json");
        var error = await InvokeAsync(status, content);
        Assert.Contains("HTTP status", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(content.ReadAttempted);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("application/json")]
    [InlineData("application/octet-stream")]
    [InlineData("application/timestamp-query")]
    [InlineData("application/timestamp-response")] // RFC 3161 verified erratum EID 1879
    [InlineData("application/timestamp-reply-evil")]
    public async Task MissingOrWrongMimeIsDeniedBeforeReadingBody(string? mime)
    {
        using var content = new ReadDeniedContent(mime);
        var error = await InvokeAsync(HttpStatusCode.OK, content);
        Assert.Contains("Content-Type", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(content.ReadAttempted);
    }

    [Theory]
    [InlineData("application/timestamp-reply")]
    [InlineData("Application/TimeStamp-Reply")]
    [InlineData("application/timestamp-reply; name=receipt.tsr")]
    public async Task CorrectMimeWithOptionalParameterReachesExistingDerVerifier(string mime)
    {
        using var content = new ByteArrayContent([0x30, 0x00]); // deliberately invalid DER response
        content.Headers.ContentType = MediaTypeHeaderValue.Parse(mime);

        var error = await InvokeAsync(HttpStatusCode.OK, content);

        Assert.Contains("Malformed RFC 3161", error.Message, StringComparison.Ordinal);
    }

    private static async Task<TimestampProviderResponseException> InvokeAsync(
        HttpStatusCode status, HttpContent content)
    {
        using var http = new HttpClient(new ReplyHandler(status, content));
        var provider = CreateProvider(http);
        return await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
    }

    private static ExternalRfc3161TimestampProvider CreateProvider(HttpClient http) =>
        new ExternalRfc3161TimestampProvider(
            http, new Uri("https://tsa.example.invalid/issue"), "configured-test-tsa",
            approvedSignerCertificateSha256: new string('A', 64),
            approvedPolicyOid: "1.3.6.1.4.1.4146.2.2",
            approvedTrustAnchorCertificateBase64Der: ExternalRfc3161TrustRootTestFixture.Base64Der,
            approvedIssuerCrlBase64Der: ExternalRfc3161TrustRootTestFixture.CrlBase64Der,
            approvedRootCrlNumberFloor: "1");

    private sealed class ReplyHandler(
        HttpStatusCode status, HttpContent content, bool includeRetryAfter = false)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(status) { Content = content };
            if (includeRetryAfter)
                response.Headers.TryAddWithoutValidation("Retry-After", "999999");
            return Task.FromResult(response);
        }
    }

    /// <summary>
    /// Throws if response DER is read at all; wrong envelopes must fail first.
    /// </summary>
    private sealed class ReadDeniedContent : HttpContent
    {
        public ReadDeniedContent(string? mime)
        {
            if (mime is not null)
                Headers.ContentType = MediaTypeHeaderValue.Parse(mime);
        }

        public bool ReadAttempted { get; private set; }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
        {
            ReadAttempted = true;
            return Task.FromException(new InvalidOperationException("DER must not be read"));
        }

        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            ReadAttempted = true;
            return Task.FromException<Stream>(new InvalidOperationException("DER must not be read"));
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 2;
            return true;
        }
    }
}
