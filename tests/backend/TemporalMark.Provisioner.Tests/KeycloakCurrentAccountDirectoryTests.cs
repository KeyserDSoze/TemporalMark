using System.Net;
using System.Text;
using TemporalMark.Provisioner;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

public sealed class KeycloakCurrentAccountDirectoryTests
{
    private const string Issuer = "https://id.example.test/realms/acme";
    private const string UserId = "12345678-1234-4234-8234-123456789012";

    [Fact]
    public async Task ReadsCurrentEnabledUserAndEffectiveRealmRolesWithDedicatedServiceToken()
    {
        var calls = new List<string>();
        var handler = new Stub(async request =>
        {
            calls.Add(request.Method + " " + request.RequestUri!.AbsolutePath);
            Assert.Equal("id.example.test", request.RequestUri.Host);
            Assert.Null(request.Headers.Referrer);
            Assert.True(request.Headers.CacheControl!.NoStore);
            if (request.RequestUri.AbsolutePath.EndsWith("/token", StringComparison.Ordinal))
            {
                Assert.Equal(HttpMethod.Post, request.Method);
                Assert.Equal("Basic", request.Headers.Authorization?.Scheme);
                Assert.Contains("grant_type=client_credentials", await request.Content!.ReadAsStringAsync());
                return Json("""{"access_token":"service-token","token_type":"Bearer","expires_in":30}""");
            }
            Assert.Equal(HttpMethod.Get, request.Method);
            Assert.Equal("Bearer", request.Headers.Authorization?.Scheme);
            Assert.Equal("service-token", request.Headers.Authorization?.Parameter);
            if (request.RequestUri.AbsolutePath.EndsWith("/composite", StringComparison.Ordinal))
                return Json("""[{"name":"tenant_admin"},{"name":"offline_access"}]""");
            return Json("""{"id":"12345678-1234-4234-8234-123456789012","enabled":true}""");
        });
        using var directory = new KeycloakCurrentAccountDirectory(Issuer, false,
            "client", "secret", handler);
        var state = await directory.GetAccountAsync(Issuer, UserId, default);
        Assert.True(state.Enabled);
        Assert.Equal(Issuer, state.Issuer);
        Assert.Equal(UserId, state.Subject);
        Assert.Contains("tenant_admin", state.EffectiveRealmRoles);
        Assert.Equal(3, calls.Count);
        Assert.Equal("POST /realms/acme/protocol/openid-connect/token", calls[0]);
        Assert.EndsWith("/users/" + UserId, calls[1]);
        Assert.EndsWith("/users/" + UserId + "/role-mappings/realm/composite", calls[2]);
    }

    [Fact]
    public async Task DisabledUserNeverFetchesRoleAssignments()
    {
        var count = 0;
        var handler = new Stub(request =>
        {
            count++;
            return Task.FromResult(request.RequestUri!.AbsolutePath.EndsWith("/token") ?
                Json("""{"access_token":"a-valid-token"}""") :
                Json("""{"id":"12345678-1234-4234-8234-123456789012","enabled":false}"""));
        });
        using var directory = new KeycloakCurrentAccountDirectory(Issuer, false,
            "client", "secret", handler);
        var result = await directory.GetAccountAsync(Issuer, UserId, default);
        Assert.False(result.Enabled);
        Assert.Empty(result.EffectiveRealmRoles);
        Assert.Equal(2, count);
    }

    [Theory]
    [InlineData("wrong-user")]
    [InlineData("missing-enabled")]
    [InlineData("bad-user-json")]
    [InlineData("missing-service-token")]
    [InlineData("denied-roles")]
    [InlineData("bad-roles-json")]
    [InlineData("roles-redirect")]
    [InlineData("service-down")]
    public async Task DirectoryFailuresCannotBeInterpretedAsAuthorization(string failure)
    {
        var handler = new Stub(request =>
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/token", StringComparison.Ordinal))
                return Task.FromResult(failure == "missing-service-token" ?
                    Json("""{"access_token":null}""") :
                    failure == "service-down" ? Json("{}", HttpStatusCode.ServiceUnavailable) :
                    Json("""{"access_token":"service-token"}"""));
            if (path.EndsWith("/composite", StringComparison.Ordinal))
                return Task.FromResult(failure switch
                {
                    "denied-roles" => Json("{}", HttpStatusCode.Forbidden),
                    "bad-roles-json" => Json("""{"name":"tenant_admin"}"""),
                    "roles-redirect" => Json("{}", HttpStatusCode.Redirect),
                    _ => Json("""[{"name":"tenant_admin"}]""")
                });
            return Task.FromResult(failure switch
            {
                "wrong-user" => Json("""{"id":"00000000-0000-0000-0000-000000000001","enabled":true}"""),
                "missing-enabled" => Json("""{"id":"12345678-1234-4234-8234-123456789012"}"""),
                "bad-user-json" => Json("{broken"),
                _ => Json("""{"id":"12345678-1234-4234-8234-123456789012","enabled":true}""")
            });
        });
        using var directory = new KeycloakCurrentAccountDirectory(Issuer, false,
            "client", "secret", handler);
        await Assert.ThrowsAnyAsync<Exception>(() =>
            directory.GetAccountAsync(Issuer, UserId, default));
    }

    [Fact]
    public async Task RejectsUntrustedIssuerOrInvalidSubjectBeforeNetwork()
    {
        var handler = new Stub(_ => throw new InvalidOperationException("Must not contact IdP"));
        using var directory = new KeycloakCurrentAccountDirectory(Issuer, false,
            "client", "secret", handler);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            directory.GetAccountAsync("https://other.test/realms/acme", UserId, default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            directory.GetAccountAsync(Issuer, "../admin", default));
    }

    [Fact]
    public void RemoteHttpOrUnscopedIssuerCannotConfigureDirectoryClient()
    {
        Assert.Throws<ArgumentException>(() =>
            new KeycloakCurrentAccountDirectory("http://id.example.test/realms/acme", true, "id", "secret"));
        Assert.Throws<ArgumentException>(() =>
            new KeycloakCurrentAccountDirectory("https://id.example.test/not-a-realm", false, "id", "secret"));
        Assert.Throws<ArgumentException>(() =>
            new KeycloakCurrentAccountDirectory(Issuer, false, "id", ""));
        Assert.Throws<ArgumentException>(() =>
            new KeycloakCurrentAccountDirectory(Issuer, false, "bad:id", "secret"));
    }

    private static HttpResponseMessage Json(string json, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };

    private sealed class Stub(Func<HttpRequestMessage, Task<HttpResponseMessage>> handler)
        : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken) => handler(request);
    }
}
