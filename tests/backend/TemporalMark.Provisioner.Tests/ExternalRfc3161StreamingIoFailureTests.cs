using System.IO;
using System.Net;
using System.Net.Http.Headers;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first #99. A 200 timestamp-reply with broken transport bytes must
/// never become a receipt, raw IOException disclosure or unhandled HTTP 500.
/// All trust configuration uses disposable local test-only PKI.
/// </summary>
public sealed class ExternalRfc3161StreamingIoFailureTests
{
    [Theory]
    [InlineData("send")]
    [InlineData("open")]
    [InlineData("partial")]
    [InlineData("cancel-send")]
    [InlineData("cancel-open")]
    [InlineData("cancel-partial")]
    public async Task BrokenOutboundOrInboundTsaStreamIsSanitizedAsUnavailable(string fault)
    {
        using var handler = new FaultHandler(fault);
        using var http = new HttpClient(handler);
        var provider = CreateConfiguredProvider(http);

        var error = await Assert.ThrowsAsync<TimestampProviderUnavailableException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));

        Assert.Equal(1, handler.Sends);
        Assert.Contains("TSA", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("private", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("socket", error.Message, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("raw", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task OrdinaryMalformedCompleteDerStillMapsToResponseError()
    {
        using var handler = new FaultHandler("malformed");
        using var http = new HttpClient(handler);
        var provider = CreateConfiguredProvider(http);

        await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            provider.RequestAsync(new byte[32], CancellationToken.None));
        Assert.Equal(1, handler.Sends);
    }

    [Fact]
    public async Task ExplicitCallerCancellationMustNotBeRecastAsTsaOutage()
    {
        using var handler = new FaultHandler("malformed");
        using var http = new HttpClient(handler);
        var provider = CreateConfiguredProvider(http);
        using var canceled = new CancellationTokenSource();
        canceled.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            provider.RequestAsync(new byte[32], canceled.Token));
        Assert.Equal(0, handler.Sends);
    }

    [Fact]
    public async Task CallerCancelsAfterPartialBodyAndCancellationPropagates()
    {
        using var callerCancellation = new CancellationTokenSource();
        using var handler = new FaultHandler("caller-read", callerCancellation);
        using var http = new HttpClient(handler);
        var provider = CreateConfiguredProvider(http);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            provider.RequestAsync(new byte[32], callerCancellation.Token));
        Assert.True(callerCancellation.IsCancellationRequested);
        Assert.Equal(1, handler.Sends);
    }

    private static ExternalRfc3161TimestampProvider CreateConfiguredProvider(HttpClient http) =>
        new(http, new Uri("https://tsa.example.invalid/issue"), "disposable-test-tsa",
            approvedSignerCertificateSha256:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            approvedPolicyOid: "1.3.6.1.4.1.4146.2.2",
            approvedTrustAnchorCertificateBase64Der: ExternalRfc3161TrustRootTestFixture.Base64Der,
            approvedIssuerCrlBase64Der: ExternalRfc3161TrustRootTestFixture.CrlBase64Der,
            approvedRootCrlNumberFloor: "1");

    private sealed class FaultHandler(string fault, CancellationTokenSource? callerCancellation = null) : HttpMessageHandler
    {
        public int Sends { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Sends++;
            if (fault == "send")
                throw new IOException("private raw socket diagnostic from test handler");
            if (fault == "cancel-send")
                throw new OperationCanceledException(
                    "private raw transport aborted without a caller cancellation");

            HttpContent content = fault == "malformed"
                ? new ByteArrayContent([0x30, 0x00])
                : new FaultContent(fault, callerCancellation);

            content.Headers.ContentType =
                new MediaTypeHeaderValue("application/timestamp-reply");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = content
            });
        }
    }

    private sealed class FaultContent(string fault, CancellationTokenSource? callerCancellation) : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            Task.FromException(new IOException("private raw socket serialization error"));

        protected override Task<Stream> CreateContentReadStreamAsync()
        {
            if (fault == "open")
                return Task.FromException<Stream>(
                    new IOException("private raw socket stream acquisition error"));
            if (fault == "cancel-open")
                return Task.FromException<Stream>(
                    new OperationCanceledException(
                        "private raw stream acquisition aborted by upstream"));
            return Task.FromResult<Stream>(
                new PrefixThenFaultStream(fault, callerCancellation));
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private sealed class PrefixThenFaultStream(string fault, CancellationTokenSource? callerCancellation)
        : MemoryStream(new byte[] { 0x30, 0x00 })
    {
        public override ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowAtBodyTail(cancellationToken);
            return base.ReadAsync(buffer, cancellationToken);
        }

        public override Task<int> ReadAsync(
            byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowAtBodyTail(cancellationToken);
            return base.ReadAsync(buffer, offset, count, cancellationToken);
        }

        private void ThrowAtBodyTail(CancellationToken cancellationToken)
        {
            if (Position < Length)
                return;
            if (fault == "caller-read")
            {
                callerCancellation!.Cancel();
                cancellationToken.ThrowIfCancellationRequested();
            }
            if (fault == "cancel-partial")
                throw new OperationCanceledException(
                    "private raw upstream canceled after partial DER");
            throw new IOException("private raw socket lost after partial DER");
        }
    }
}
