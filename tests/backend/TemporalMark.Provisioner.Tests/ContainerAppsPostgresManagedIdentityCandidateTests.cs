using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// #131 / ADR 0097 RED first: ACA managed-identity endpoint integration is
/// simulated with an in-memory handler, no Azure account or PostgreSQL socket.
/// </summary>
public sealed class ContainerAppsPostgresManagedIdentityCandidateTests
{
    private const string Endpoint = "http://localhost:42356/msi/token";
    private const string IdentityHeader = "FAKE-ACA-ROTATING-HEADER-CANARY";
    private const string Resource = "https://ossrdbms-aad.database.windows.net";
    private const string Scope = Resource + "/.default";
    private const string ClientId = "22222222-2222-4222-8222-222222222222";
    private static readonly Guid IdentityId = Guid.Parse(ClientId);
    private static readonly DateTimeOffset Now = new(2026, 11, 20, 19, 0, 0, TimeSpan.Zero);

    private static string Json(long expiresOn, string? token = "FAKE-OPAQUE-NOT-A-JWT",
        string? resource = Resource, string? tokenType = "Bearer", string? clientId = ClientId) =>
        JsonSerializer.Serialize(new
        {
            access_token = token,
            expires_on = expiresOn.ToString(System.Globalization.CultureInfo.InvariantCulture),
            resource,
            token_type = tokenType,
            client_id = clientId
        });

    private static HttpResponseMessage Response(string body, HttpStatusCode status = HttpStatusCode.OK,
        string contentType = "application/json")
    {
        var response = new HttpResponseMessage(status)
        {
            Content = new StringContent(body, Encoding.UTF8, contentType)
        };
        return response;
    }

    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private sealed class FakeHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send)
        : HttpMessageHandler
    {
        public int Count { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Count++;
            return send(request, cancellationToken);
        }
    }

    private static ContainerAppsPostgresManagedIdentityCandidate Create(FakeHandler handler) =>
        ContainerAppsPostgresManagedIdentityCandidate.CreateForTests(
            handler, Endpoint, IdentityHeader, IdentityId, new Clock());

    [Fact]
    public async Task RequestsExactlyPostgresResourceWithApprovedUserAssignedClientAndIdentityHeader()
    {
        var fake = new FakeHandler((request, _) =>
        {
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("localhost", request.RequestUri!.Host);
            Assert.Equal("/msi/token", request.RequestUri.AbsolutePath);
            Assert.Contains("api-version=2019-08-01", request.RequestUri.Query);
            Assert.Contains("resource=https%3A%2F%2Fossrdbms-aad.database.windows.net",
                request.RequestUri.Query, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("client_id=" + ClientId, request.RequestUri.Query);
            Assert.DoesNotContain(IdentityHeader, request.RequestUri.ToString());
            Assert.Single(request.Headers.GetValues("X-IDENTITY-HEADER"));
            Assert.Equal(IdentityHeader, request.Headers.GetValues("X-IDENTITY-HEADER").Single());
            Assert.Null(request.Content);
            return Task.FromResult(Response(Json(Now.AddMinutes(8).ToUnixTimeSeconds())));
        });
        using var client = Create(fake);
        var token = await client.GetTokenAsync(Scope, CancellationToken.None);
        Assert.Equal("FAKE-OPAQUE-NOT-A-JWT", token);
        Assert.Equal(1, fake.Count);
    }

    [Fact]
    public async Task CompatibleWithDetachedNpgsqlCandidateWithoutOpeningSqlConnection()
    {
        var fake = new FakeHandler((_, _) =>
            Task.FromResult(Response(Json(Now.AddMinutes(10).ToUnixTimeSeconds()))));
        using var identity = Create(fake);
        using var dataSource = EntraPostgresDataSourceCandidate.Create(
            "Host=tm-ci-pg.postgres.database.azure.com;Port=5432;Database=temporalmark;" +
            "Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable",
            identity.GetTokenAsync);
        Assert.NotNull(dataSource);
        Assert.Equal(0, fake.Count);
        var token = await identity.GetTokenAsync(Scope, CancellationToken.None);
        Assert.Equal("FAKE-OPAQUE-NOT-A-JWT", token);
        Assert.Equal(1, fake.Count);
    }

    [Theory]
    [InlineData("https://localhost:42356/msi/token")]
    [InlineData("http://evil.example.net:42356/msi/token")]
    [InlineData("http://169.254.169.254:42356/metadata/identity/oauth2/token")]
    [InlineData("http://127.0.0.2:42356/msi/token")]
    [InlineData("http://10.0.0.1:42356/msi/token")]
    [InlineData("http://localhost/msi/token")]
    [InlineData("http://localhost:42356")]
    [InlineData("http://localhost:42356/msi/token?resource=https://evil")]
    [InlineData("http://localhost:42356/msi/token#secret")]
    [InlineData("http://user:password@localhost:42356/msi/token")]
    [InlineData("http://localhost.evil.example:42356/msi/token")]
    [InlineData("http://localhost:42356/../?leak=token")]
    [InlineData("file:///tmp/identity")]
    public void RejectsNonLocalOrInjectedIdentityEndpoint(string endpoint)
    {
        var fake = new FakeHandler((_, _) => throw new Exception("SHOULD-NOT-ISSUE-REQUEST"));
        var error = Assert.Throws<ArgumentException>(() =>
            ContainerAppsPostgresManagedIdentityCandidate.CreateForTests(
                fake, endpoint, IdentityHeader, IdentityId, new Clock()));
        Assert.DoesNotContain("password@", error.ToString());
        Assert.Equal(0, fake.Count);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("HEADER\r\nX-Evil: secret")]
    [InlineData("HEADER\u0000BINARY")]
    public void RejectsMissingOrInjectedIdentityHeader(string header)
    {
        var fake = new FakeHandler((_, _) => throw new Exception("SHOULD-NOT-ISSUE-REQUEST"));
        Assert.Throws<ArgumentException>(() =>
            ContainerAppsPostgresManagedIdentityCandidate.CreateForTests(
                fake, Endpoint, header, IdentityId, new Clock()));
        Assert.Equal(0, fake.Count);
    }

    [Fact]
    public void RejectsMissingManagedIdentityClientIdInsteadOfDefaultingToSystemIdentity()
    {
        var fake = new FakeHandler((_, _) => throw new Exception("SHOULD-NOT-ISSUE-REQUEST"));
        Assert.Throws<ArgumentException>(() =>
            ContainerAppsPostgresManagedIdentityCandidate.CreateForTests(
                fake, Endpoint, IdentityHeader, Guid.Empty, new Clock()));
    }

    [Theory]
    [InlineData("https://management.azure.com/.default")]
    [InlineData("https://ossrdbms-aad.database.windows.net")]
    [InlineData("https://vault.azure.net/.default")]
    [InlineData("")]
    public async Task RejectsIncorrectAudienceWithoutCallingIdentityEndpoint(string suppliedScope)
    {
        var fake = new FakeHandler((_, _) => throw new Exception("SHOULD-NOT-ISSUE-REQUEST"));
        using var client = Create(fake);
        await Assert.ThrowsAsync<ArgumentException>(
            async () => await client.GetTokenAsync(suppliedScope, CancellationToken.None));
        Assert.Equal(0, fake.Count);
    }

    [Theory]
    [InlineData("https://management.azure.com", "Bearer", ClientId)]
    [InlineData(Resource, "Basic", ClientId)]
    [InlineData(Resource, "Bearer", "99999999-9999-4999-8999-999999999999")]
    [InlineData(Resource, "Bearer", null)]
    public async Task RejectsWrongResourceTokenTypeOrUserAssignedIdentity(
        string resource, string type, string? clientId)
    {
        var fake = new FakeHandler((_, _) => Task.FromResult(
            Response(Json(Now.AddMinutes(8).ToUnixTimeSeconds(),
                resource: resource, tokenType: type, clientId: clientId))));
        using var client = Create(fake);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("FAKE-OPAQUE-NOT-A-JWT", error.ToString());
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("BEARER\nSECRET")]
    [InlineData("BAD\u0000TOKEN")]
    public async Task RejectsBlankOrControlCharacterAccessTokens(string token)
    {
        var fake = new FakeHandler((_, _) => Task.FromResult(
            Response(Json(Now.AddMinutes(8).ToUnixTimeSeconds(), token: token))));
        using var client = Create(fake);
        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.GetTokenAsync(Scope, CancellationToken.None));
    }

    [Theory]
    [InlineData(-30)]
    [InlineData(0)]
    [InlineData(60)]
    [InlineData(119)]
    [InlineData(90000)]
    public async Task RejectsExpiredNearExpiryOrUnreasonablyFutureToken(int secondsFromNow)
    {
        var fake = new FakeHandler((_, _) => Task.FromResult(
            Response(Json(Now.AddSeconds(secondsFromNow).ToUnixTimeSeconds()))));
        using var client = Create(fake);
        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.GetTokenAsync(Scope, CancellationToken.None));
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.Found)]
    [InlineData(HttpStatusCode.InternalServerError)]
    public async Task NoRetryRedirectOrSecretLeakOnIdentityServiceFailure(HttpStatusCode status)
    {
        var fake = new FakeHandler((_, _) => Task.FromResult(
            Response("ERROR-CANARY-BEARER-SUPER-SECRET", status)));
        using var client = Create(fake);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("ERROR-CANARY-BEARER-SUPER-SECRET", error.ToString());
        Assert.Equal(1, fake.Count);
    }

    [Fact]
    public async Task RejectsOversizedOrMalformedResponseWithoutLeakingContent()
    {
        var fake = new FakeHandler((_, _) => Task.FromResult(
            Response("{\"access_token\":\"CANARY-\"" + new string('X', 90000))));
        using var client = Create(fake);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("CANARY-", error.ToString());
    }

    [Fact]
    public async Task RejectsUnparseableExpiryWithoutLeakingToken()
    {
        var fake = new FakeHandler((_, _) => Task.FromResult(Response(
            "{\"access_token\":\"SECRET-CANARY\",\"resource\":\"" + Resource +
            "\",\"client_id\":\"" + ClientId +
            "\",\"token_type\":\"Bearer\",\"expires_on\":\"NOT-A-TIME\"}")));
        using var client = Create(fake);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("SECRET-CANARY", error.ToString());
    }

    // #138 / ADR 0103: these tests intentionally RED against the old
    // TryGetProperty-last-wins parser. A credential response must be unambiguous.
    [Theory]
    [InlineData("access_token")]
    [InlineData("expires_on")]
    [InlineData("resource")]
    [InlineData("token_type")]
    [InlineData("client_id")]
    public async Task RejectsExactDuplicateJsonPropertiesEvenWhenLastValueLooksApproved(string key)
    {
        var valid = Json(Now.AddMinutes(8).ToUnixTimeSeconds());
        var ambiguous = valid.Insert(1, "\"" + key + "\":\"DECOY-SECRET-CANARY\",");
        var fake = new FakeHandler((_, _) => Task.FromResult(Response(ambiguous)));
        using var client = Create(fake);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("DECOY-SECRET-CANARY", error.ToString());
        Assert.DoesNotContain(IdentityHeader, error.ToString());
        Assert.Equal(1, fake.Count);
    }

    [Theory]
    [InlineData("Access_Token")]
    [InlineData("Expires_On")]
    [InlineData("Resource")]
    [InlineData("Token_Type")]
    [InlineData("Client_Id")]
    public async Task RejectsCaseVariantOfCanonicalTokenJsonProperty(string alternateName)
    {
        var valid = Json(Now.AddMinutes(8).ToUnixTimeSeconds());
        var ambiguous = valid.Insert(1, "\"" + alternateName + "\":\"DECOY-SECRET-CANARY\",");
        var fake = new FakeHandler((_, _) => Task.FromResult(Response(ambiguous)));
        using var client = Create(fake);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("DECOY-SECRET-CANARY", error.ToString());
        Assert.Equal(1, fake.Count);
    }

    [Fact]
    public async Task RejectsEvenMatchingDuplicateValueRatherThanTrustingLastOccurrence()
    {
        var valid = Json(Now.AddMinutes(8).ToUnixTimeSeconds());
        var ambiguous = valid.Insert(1, "\"token_type\":\"Bearer\",");
        var fake = new FakeHandler((_, _) => Task.FromResult(Response(ambiguous)));
        using var client = Create(fake);

        await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Equal(1, fake.Count);
    }

    [Fact]
    public async Task AllowsDistinctOptionalAzureMetadataWithoutWeakeningRequiredResponseChecks()
    {
        var valid = Json(Now.AddMinutes(8).ToUnixTimeSeconds());
        var extended = valid.Insert(valid.Length - 1, ",\"unknown_future_field\":\"synthetic\"");
        var fake = new FakeHandler((_, _) => Task.FromResult(Response(extended)));
        using var client = Create(fake);

        Assert.Equal("FAKE-OPAQUE-NOT-A-JWT",
            await client.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Equal(1, fake.Count);
    }

    [Fact]
    public async Task TransportExceptionsCannotLeakPlatformHeaderOrToken()
    {
        var fake = new FakeHandler((_, _) =>
            throw new HttpRequestException("LEAKED-" + IdentityHeader + "-BEARER-CANARY"));
        using var client = Create(fake);
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await client.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain(IdentityHeader, error.ToString());
        Assert.DoesNotContain("BEARER-CANARY", error.ToString());
    }

    [Fact]
    public async Task ExplicitCallerCancellationPropagatesAndDoesNotRetry()
    {
        var fake = new FakeHandler((_, ct) => throw new OperationCanceledException(ct));
        using var client = Create(fake);
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await client.GetTokenAsync(Scope, cancelled.Token));
        Assert.Equal(0, fake.Count);
    }


    // #139 / ADR 0104: a fast 200/JSON header can precede a forever-stalling
    // response stream. HttpClient.Timeout with ResponseHeadersRead alone does
    // NOT bound the subsequent content read; these tests were committed RED.
    private sealed class NeverFinishingJsonStream : Stream
    {
        public int ReadAttempts { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            ReadAttempts++;
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count,
            CancellationToken cancellationToken) =>
            ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

    private static HttpResponseMessage StallingJsonBody(NeverFinishingJsonStream stream)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(stream)
        };
        response.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        return response;
    }

    [Fact]
    public async Task StalledBodyAfterSuccessfulHeadersFailsClosedWithinOneTotalDeadline()
    {
        var stream = new NeverFinishingJsonStream();
        var fake = new FakeHandler((_, _) => Task.FromResult(StallingJsonBody(stream)));
        using var candidate = ContainerAppsPostgresManagedIdentityCandidate.CreateForTests(
            fake, Endpoint, IdentityHeader, IdentityId, new Clock(),
            TimeSpan.FromMilliseconds(60));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await candidate.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain(IdentityHeader, error.ToString());
        Assert.DoesNotContain("access_token", error.ToString());
        Assert.Equal(1, fake.Count);
        Assert.True(stream.ReadAttempts > 0);
    }

    [Fact]
    public async Task StalledHeadersUseSameOverallDeadlineWithoutRetry()
    {
        var fake = new FakeHandler(async (_, ct) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, ct);
            return Response("UNREACHABLE-SECRET-CANARY");
        });
        using var candidate = ContainerAppsPostgresManagedIdentityCandidate.CreateForTests(
            fake, Endpoint, IdentityHeader, IdentityId, new Clock(),
            TimeSpan.FromMilliseconds(60));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await candidate.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("UNREACHABLE-SECRET-CANARY", error.ToString());
        Assert.Equal(1, fake.Count);
    }

    [Fact]
    public async Task ExplicitCallerCancellationDuringBodyStillPropagates()
    {
        var stream = new NeverFinishingJsonStream();
        var fake = new FakeHandler((_, _) => Task.FromResult(StallingJsonBody(stream)));
        using var candidate = ContainerAppsPostgresManagedIdentityCandidate.CreateForTests(
            fake, Endpoint, IdentityHeader, IdentityId, new Clock(),
            TimeSpan.FromSeconds(2));
        using var caller = new CancellationTokenSource();
        caller.CancelAfter(TimeSpan.FromMilliseconds(60));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await candidate.GetTokenAsync(Scope, caller.Token));
        Assert.Equal(1, fake.Count);
        Assert.True(stream.ReadAttempts > 0);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(11000)]
    public void RejectsNonPositiveOrRelaxedTestOnlyDeadlines(int milliseconds)
    {
        var fake = new FakeHandler((_, _) =>
            throw new InvalidOperationException("SHOULD-NOT-CONNECT"));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            ContainerAppsPostgresManagedIdentityCandidate.CreateForTests(
                fake, Endpoint, IdentityHeader, IdentityId, new Clock(),
                TimeSpan.FromMilliseconds(milliseconds)));
        Assert.Equal(0, fake.Count);
    }

    [Fact]
    public async Task ShortTestDeadlineStillAcceptsImmediatelyCompleteCorrectTokenJson()
    {
        var fake = new FakeHandler((_, _) =>
            Task.FromResult(Response(Json(Now.AddMinutes(8).ToUnixTimeSeconds()))));
        using var candidate = ContainerAppsPostgresManagedIdentityCandidate.CreateForTests(
            fake, Endpoint, IdentityHeader, IdentityId, new Clock(),
            TimeSpan.FromSeconds(1));

        Assert.Equal("FAKE-OPAQUE-NOT-A-JWT",
            await candidate.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Equal(1, fake.Count);
    }

    [Fact]
    public async Task EverySuccessfulRequestGetsNewTokenInsteadOfCaching()
    {
        var fake = new FakeHandler((_, _) => Task.FromResult(
            Response(Json(Now.AddMinutes(8).ToUnixTimeSeconds()))));
        using var client = Create(fake);
        Assert.Equal("FAKE-OPAQUE-NOT-A-JWT",
            await client.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Equal("FAKE-OPAQUE-NOT-A-JWT",
            await client.GetTokenAsync(Scope, CancellationToken.None));
        Assert.Equal(2, fake.Count);
    }

    [Fact]
    public void ProductionHandlerDeniesAmbientProxyRedirectCookiesAndPinsLoopback()
    {
        using var handler = ContainerAppsPostgresManagedIdentityCandidate.CreateHardenedHandler();
        Assert.False(handler.UseProxy);
        Assert.Null(handler.Proxy);
        Assert.False(handler.AllowAutoRedirect);
        Assert.False(handler.UseCookies);
        Assert.Equal(DecompressionMethods.None, handler.AutomaticDecompression);
        Assert.NotNull(handler.ConnectCallback);
        Assert.Null(handler.Credentials);
    }

    [Fact]
    public void PublicFactoryNeverReadsAmbientDefaultManagedIdentity()
    {
        using var candidate = ContainerAppsPostgresManagedIdentityCandidate.Create(
            Endpoint, IdentityHeader, IdentityId, new Clock());
        Assert.NotNull(candidate);
    }
}
