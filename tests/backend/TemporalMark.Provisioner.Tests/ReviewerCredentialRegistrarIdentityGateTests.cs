using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using TemporalMark.Business.Tenancy;
using TemporalMark.Provisioner;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED before gate exists. RS256 signatures are verified by the real production
/// token verifier; live/directory state is supplied by adversarial fakes.
/// No SQL, registrar grant, WebAuthn key or enrollment takes place.
/// </summary>
public sealed class ReviewerCredentialRegistrarIdentityGateTests : IDisposable
{
    private const string Issuer = "https://auth.example.test/realms/registrar";
    private const string RegistrarAudience = "temporalmark-credential-registrar";
    private const string ReviewerAudience = "temporalmark-approval";
    private const string RequiredAcr = "urn:temporalmark:loa:2";
    private const string RegistrarSub = "12445678-1234-4234-8234-123456789012";
    private const string ReviewerSub = "22445678-1234-4234-8234-123456789012";
    private readonly RSA rsa = RSA.Create(2048);
    private readonly RsaSecurityKey key;
    private readonly StubLive live = new();
    private readonly StubDirectory directory = new();

    public ReviewerCredentialRegistrarIdentityGateTests() =>
        key = new RsaSecurityKey(rsa) { KeyId = "trusted-registrar-signing-key" };

    private ReviewerCredentialRegistrarIdentityGate Gate()
    {
        var metadata = new OpenIdConnectConfiguration { Issuer = Issuer };
        metadata.SigningKeys.Add(key);
        var verifier = new OidcAccessTokenVerifier(Issuer, false, new StaticConfiguration(metadata));
        return new ReviewerCredentialRegistrarIdentityGate(verifier, live, directory,
            new RegistrarIdentityGatePolicy(Issuer, RegistrarAudience, ReviewerAudience, RequiredAcr));
    }

    private string Signed(string subject, string role, string audience,
        string? acr = RequiredAcr, long? authTime = null, RsaSecurityKey? signer = null)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var claims = new List<Claim>
        {
            new("sub", subject), new("role", role), new("typ", "Bearer")
        };
        if (acr is not null) claims.Add(new Claim("acr", acr));
        if (authTime.HasValue)
            claims.Add(new Claim("auth_time", authTime.Value.ToString(),
                ClaimValueTypes.Integer64));
        else
            claims.Add(new Claim("auth_time", (now - 20).ToString(),
                ClaimValueTypes.Integer64));
        var issued = DateTime.UtcNow.AddSeconds(-10);
        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer, Audience = audience, Subject = new ClaimsIdentity(claims),
            IssuedAt = issued, NotBefore = issued, Expires = DateTime.UtcNow.AddMinutes(2),
            SigningCredentials = new SigningCredentials(signer ?? key, SecurityAlgorithms.RsaSha256)
        });
    }

    private string Registrar(string? acr = RequiredAcr, long? authTime = null) =>
        Signed(RegistrarSub, "platform_credential_registrar", RegistrarAudience, acr, authTime);
    private string Reviewer(string? acr = RequiredAcr, long? authTime = null) =>
        Signed(ReviewerSub, "platform_approver", ReviewerAudience, acr, authTime);
    private static RegistrarRegistrationIdentityScope Scope() => new(ReviewerSub);

    [Fact]
    public void DisposableMfaRealmHttpRequiresExplicitExactHardcodedTestOptIn()
    {
        const string fixtureIssuer = "http://localhost:8081/realms/temporalmark-mfa-ci";
        Assert.Throws<ArgumentException>(() => new RegistrarIdentityGatePolicy(
            fixtureIssuer, RegistrarAudience, ReviewerAudience, RequiredAcr));
        var approved = new RegistrarIdentityGatePolicy(
            fixtureIssuer, RegistrarAudience, ReviewerAudience, RequiredAcr,
            allowDisposableMfaCiLoopbackHttp: true);
        Assert.Equal(fixtureIssuer, approved.Issuer);

        foreach (var issuer in new[]
        {
            "http://localhost:8081/realms/temporalmark",
            "http://127.0.0.1:8081/realms/temporalmark-mfa-ci",
            "http://localhost:8082/realms/temporalmark-mfa-ci",
            "http://attacker.test/realms/temporalmark-mfa-ci",
            "http://localhost:8081/realms/temporalmark-mfa-ci/extra"
        })
            Assert.Throws<ArgumentException>(() => new RegistrarIdentityGatePolicy(
                issuer, RegistrarAudience, ReviewerAudience, RequiredAcr,
                allowDisposableMfaCiLoopbackHttp: true));
    }

    [Fact]
    public async Task SeparateValidSignedPrincipalsRequireFreshLiveAndCurrentRealmRoles()
    {
        var proof = await Gate().CheckAsync(Registrar(), Reviewer(), Scope(), default);
        Assert.Equal(Issuer, proof.Issuer);
        Assert.Equal(RegistrarSub, proof.RegistrarSubject);
        Assert.Equal(ReviewerSub, proof.ReviewerSubject);
        Assert.True(proof.RegistrarAuthenticationTimeUnix > 0);
        Assert.True(proof.ReviewerAuthenticationTimeUnix > 0);
        Assert.Equal(2, live.Calls);
        Assert.Equal(2, directory.Calls);
    }

    [Fact]
    public async Task TamperedOrOtherKeySignedJwtNeverGetsToLiveStatus()
    {
        using var otherRsa = RSA.Create(2048);
        var otherKey = new RsaSecurityKey(otherRsa) { KeyId = "untrusted-other" };
        var forged = Signed(RegistrarSub, "platform_credential_registrar",
            RegistrarAudience, signer: otherKey);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(forged, Reviewer(), Scope(), default));
        Assert.Equal(0, live.Calls);
        Assert.Equal(0, directory.Calls);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task WrongAudienceOrRoleInEitherSignedPrincipalIsDenied(bool registrar)
    {
        var registrarToken = registrar
            ? Signed(RegistrarSub, "platform_approver", RegistrarAudience)
            : Registrar();
        var reviewerToken = registrar
            ? Reviewer()
            : Signed(ReviewerSub, "platform_credential_registrar", ReviewerAudience);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(registrarToken, reviewerToken, Scope(), default));

        registrarToken = registrar
            ? Signed(RegistrarSub, "platform_credential_registrar", ReviewerAudience)
            : Registrar();
        reviewerToken = registrar
            ? Reviewer()
            : Signed(ReviewerSub, "platform_approver", RegistrarAudience);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(registrarToken, reviewerToken, Scope(), default));
        Assert.Equal(0, live.Calls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("pwd")]
    [InlineData("urn:temporalmark:loa:1")]
    public async Task AnyWeakOrMissingSignedAcrIsDeniedForBothRoles(string? acr)
    {
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(Registrar(acr), Reviewer(), Scope(), default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(Registrar(), Reviewer(acr), Scope(), default));
        Assert.Equal(0, live.Calls);
    }

    [Fact]
    public async Task StaleOrFutureAuthenticationTimeCannotBecomeRegistrarAuthority()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        foreach (var badTime in new[] { now - 300, now + 100 })
        {
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                Gate().CheckAsync(Registrar(authTime: badTime), Reviewer(), Scope(), default));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                Gate().CheckAsync(Registrar(), Reviewer(authTime: badTime), Scope(), default));
        }
        Assert.Equal(0, live.Calls);
    }

    [Fact]
    public async Task SameTokenSameSubjectOrWrongExpectedReviewerCannotAuthorize()
    {
        var shared = Registrar();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(shared, shared, Scope(), default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(Registrar(), Signed(RegistrarSub, "platform_approver", ReviewerAudience),
                new RegistrarRegistrationIdentityScope(RegistrarSub), default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(Registrar(), Reviewer(),
                new RegistrarRegistrationIdentityScope("wrong-reviewer"), default));
        Assert.Equal(0, live.Calls);
    }

    [Fact]
    public async Task OriginalSqlPendingOperatorOrAdminCannotServeAsEitherPrincipal()
    {
        foreach (var blocked in new[] { RegistrarSub, ReviewerSub })
        {
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                Gate().CheckAsync(Registrar(), Reviewer(),
                    new RegistrarRegistrationIdentityScope(ReviewerSub, blocked, "other-admin"), default));
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                Gate().CheckAsync(Registrar(), Reviewer(),
                    new RegistrarRegistrationIdentityScope(ReviewerSub, "other-operator", blocked), default));
        }
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(Registrar(), Reviewer(),
                new RegistrarRegistrationIdentityScope(ReviewerSub, "only-one-excluded"), default));
        Assert.Equal(0, live.Calls);
    }

    [Theory]
    [InlineData("revoked-registrar")]
    [InlineData("revoked-reviewer")]
    [InlineData("wrong-live-issuer")]
    [InlineData("wrong-live-subject")]
    [InlineData("wrong-live-audience")]
    [InlineData("missing-live-role")]
    public async Task RevokedOrWrongIntrospectionOfEitherPrincipalFailsClosed(string failure)
    {
        live.Failure = failure;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(Registrar(), Reviewer(), Scope(), default));
        Assert.Equal(0, directory.Calls);
    }

    [Theory]
    [InlineData("disabled-registrar")]
    [InlineData("disabled-reviewer")]
    [InlineData("missing-registrar-role")]
    [InlineData("missing-reviewer-role")]
    [InlineData("wrong-dir-issuer")]
    [InlineData("wrong-dir-subject")]
    public async Task DisabledOrRemovedEffectiveDirectoryRolesFailClosed(string failure)
    {
        directory.Failure = failure;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(Registrar(), Reviewer(), Scope(), default));
    }

    [Fact]
    public async Task IdpOutageNeverFallsBackToSignedJwtOrPreviousPositiveCache()
    {
        var gate = Gate();
        await gate.CheckAsync(Registrar(), Reviewer(), Scope(), default);
        live.Failure = "network-error";
        await Assert.ThrowsAnyAsync<Exception>(() =>
            gate.CheckAsync(Registrar(), Reviewer(), Scope(), default));
        directory.Failure = "network-error";
        live.Failure = null;
        await Assert.ThrowsAnyAsync<Exception>(() =>
            gate.CheckAsync(Registrar(), Reviewer(), Scope(), default));
    }

    [Fact]
    public async Task MissingTokensAndConfigurationFailClosed()
    {
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync("", Reviewer(), Scope(), default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(Registrar(), " ", Scope(), default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Gate().CheckAsync(Registrar(), Reviewer(), null, default));
        Assert.Throws<ArgumentException>(() => new RegistrarIdentityGatePolicy(
            Issuer, RegistrarAudience, RegistrarAudience, RequiredAcr));
        Assert.Throws<ArgumentException>(() => new RegistrarIdentityGatePolicy(
            "http://attacker.test/realms/registrar", RegistrarAudience,
            ReviewerAudience, RequiredAcr));
        Assert.Throws<ArgumentException>(() => new RegistrarIdentityGatePolicy(
            Issuer, RegistrarAudience, ReviewerAudience, "pwd"));
        Assert.Equal(0, live.Calls);
    }

    public void Dispose() => rsa.Dispose();

    private sealed class StubLive : ILiveOidcTokenStatus
    {
        public string? Failure { get; set; }
        public int Calls { get; private set; }
        public Task<LiveOidcTokenState> CheckAsync(string token, string audience, CancellationToken ct)
        {
            Calls++;
            if (Failure == "network-error") throw new HttpRequestException("Unavailable");
            var registrar = audience == RegistrarAudience;
            var role = registrar ? "platform_credential_registrar" : "platform_approver";
            var sub = registrar ? RegistrarSub : ReviewerSub;
            var revoked = Failure == (registrar ? "revoked-registrar" : "revoked-reviewer");
            return Task.FromResult(new LiveOidcTokenState(!revoked,
                Failure == "wrong-live-issuer" ? "https://other.example.org" : Issuer,
                Failure == "wrong-live-subject" ? "wrong-sub" : sub,
                Failure == "wrong-live-audience" ? ["other-aud"] : [audience],
                Failure == "missing-live-role" ? ["other-role"] : [role]));
        }
    }

    private sealed class StubDirectory : ICurrentOidcAccountDirectory
    {
        public string? Failure { get; set; }
        public int Calls { get; private set; }
        public Task<CurrentOidcAccount> GetAccountAsync(string issuer, string sub, CancellationToken ct)
        {
            Calls++;
            if (Failure == "network-error") throw new HttpRequestException("Directory offline");
            var registrar = sub == RegistrarSub;
            return Task.FromResult(new CurrentOidcAccount(
                Failure == "wrong-dir-issuer" ? "https://other.example.org" : issuer,
                Failure == "wrong-dir-subject" ? "wrong-sub" : sub,
                Failure != (registrar ? "disabled-registrar" : "disabled-reviewer"),
                Failure == (registrar ? "missing-registrar-role" : "missing-reviewer-role")
                    ? ["unrelated-role"] : [registrar ? "platform_credential_registrar" : "platform_approver"]));
        }
    }

    private sealed class StaticConfiguration(OpenIdConnectConfiguration metadata)
        : IConfigurationManager<OpenIdConnectConfiguration>
    {
        public Task<OpenIdConnectConfiguration> GetConfigurationAsync(CancellationToken ct) =>
            Task.FromResult(metadata);
        public void RequestRefresh() { }
    }
}
