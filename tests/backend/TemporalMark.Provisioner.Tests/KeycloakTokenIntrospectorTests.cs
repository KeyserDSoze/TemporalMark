using System.Net;
using System.Net.Http.Headers;
using System.Text;
using TemporalMark.Provisioner;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

public sealed class KeycloakTokenIntrospectorTests
{
    private const string Issuer = "https://auth.example.test/realms/temporalmark";

    [Fact]
    public async Task RequiresConfidentialPostToIssuerWithNoCachingAndParsesIdentity()
    {
        var handler = new StubHandler(async request =>
        {
            Assert.Equal(HttpMethod.Post, request.Method);
            Assert.Equal(Issuer + "/protocol/openid-connect/token/introspect", request.RequestUri?.ToString());
            Assert.Equal("Basic", request.Headers.Authorization?.Scheme);
            Assert.Equal(
                Convert.ToBase64String(Encoding.UTF8.GetBytes("trusted-introspector:sealed-secret")),
                request.Headers.Authorization?.Parameter);
            Assert.True(request.Headers.CacheControl?.NoStore);
            Assert.Equal("application/x-www-form-urlencoded", request.Content?.Headers.ContentType?.MediaType);
            var form = await request.Content!.ReadAsStringAsync();
            Assert.Contains("token=valid-token", form);
            Assert.Contains("token_type_hint=access_token", form);
            return JsonResponse("""{"active":true,"iss":"https://auth.example.test/realms/temporalmark","sub":"first-admin","aud":["temporalmark-api","trusted-introspector"],"role":["tenant_admin"]}""");
        });
        using var live = new KeycloakTokenIntrospector(Issuer, false, "trusted-introspector", "sealed-secret", handler);
        var state = await live.CheckAsync("valid-token", "temporalmark-api", default);
        Assert.True(state.Active);
        Assert.Equal(Issuer, state.Issuer);
        Assert.Equal("first-admin", state.Subject);
        Assert.Contains("temporalmark-api", state.Audiences);
        Assert.Contains("tenant_admin", state.Roles);
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task ReturnsInactiveWithoutTrustingUnexpectedClaims()
    {
        using var live = new KeycloakTokenIntrospector(Issuer, false, "client", "secret",
            new StubHandler(_ => Task.FromResult(JsonResponse("""{"active":false,"sub":"forged-user"}"""))));
        var state = await live.CheckAsync("expired", "temporalmark-api", default);
        Assert.False(state.Active);
        Assert.Null(state.Subject);
    }

    [Theory]
    [InlineData(302, "{}")]
    [InlineData(401, "{}")]
    [InlineData(500, "{}")]
    [InlineData(200, "{bad json}")]
    [InlineData(200, "{}")]
    [InlineData(200, "{\"active\":\"true\"}")]
    public async Task HttpFailuresOrMalformedLiveStatusFailClosed(int code, string json)
    {
        using var live = new KeycloakTokenIntrospector(Issuer, false, "client", "secret",
            new StubHandler(_ => Task.FromResult(JsonResponse(json, (HttpStatusCode)code))));
        await Assert.ThrowsAnyAsync<Exception>(() => live.CheckAsync("token", "temporalmark-api", default));
    }

    [Fact]
    public async Task OversizedResponseIsRejected()
    {
        var response = "{\"active\":true,\"junk\":\"" + new string('x', 20000) + "\"}";
        using var live = new KeycloakTokenIntrospector(Issuer, false, "client", "secret",
            new StubHandler(_ => Task.FromResult(JsonResponse(response))));
        await Assert.ThrowsAnyAsync<Exception>(() => live.CheckAsync("token", "temporalmark-api", default));
    }

    [Fact]
    public void InsecureRemoteIssuerOrMissingSecretIsRejected()
    {
        Assert.Throws<ArgumentException>(() =>
            new KeycloakTokenIntrospector("http://auth.example.test/realms/a", true, "id", "secret"));
        Assert.Throws<ArgumentException>(() =>
            new KeycloakTokenIntrospector(Issuer, false, "id", ""));
        Assert.Throws<ArgumentException>(() =>
            new KeycloakTokenIntrospector(Issuer, false, "bad:id", "secret"));
    }

    private static HttpResponseMessage JsonResponse(string body, HttpStatusCode code = HttpStatusCode.OK) =>
        new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class StubHandler(Func<HttpRequestMessage, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls++;
            return respond(request);
        }
    }
}
