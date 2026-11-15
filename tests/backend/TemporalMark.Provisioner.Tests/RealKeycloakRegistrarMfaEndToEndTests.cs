using TemporalMark.Business.Tenancy;
using TemporalMark.Provisioner;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// Disposable CI ONLY. Real Keycloak browser+TOTP+S256-PKCE tokens must pass
/// production signed-token, live RFC7662 and CURRENT Keycloak directory checks
/// for TWO different principals. CI later removes registrar roles / disables it
/// AFTER issuing the same tokens: replay of old bearer MUST be denied.
/// No SQL challenge is issued and no WebAuthn key is registered.
/// </summary>
public sealed class RealKeycloakRegistrarMfaEndToEndTests
{
    private const string Issuer = RegistrarIdentityGatePolicy.DisposableMfaCiIssuer;
    private const string RegistrarSubject = "00000000-0000-0000-0000-000000000035";
    private const string ReviewerSubject = "00000000-0000-0000-0000-000000000034";

    [Fact]
    public async Task BrowserMfaRegistrarAndReviewerRequireSignedLiveCurrentRoles()
    {
        var registrarPath = Environment.GetEnvironmentVariable("TEMPORALMARK_CI_REGISTRAR_TOKEN_FILE");
        var reviewerPath = Environment.GetEnvironmentVariable("TEMPORALMARK_CI_MFA_TOKEN_FILE");
        // Ordinary developer unit test runs must not use a network fixture.
        if (string.IsNullOrEmpty(registrarPath) && string.IsNullOrEmpty(reviewerPath)) return;
        Assert.False(string.IsNullOrEmpty(registrarPath));
        Assert.False(string.IsNullOrEmpty(reviewerPath));

        foreach (var file in new[] { registrarPath!, reviewerPath! })
        {
            Assert.True(File.Exists(file), "A verified browser MFA bearer is required.");
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                var mode = File.GetUnixFileMode(file);
                const UnixFileMode forbidden =
                    UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                    UnixFileMode.GroupExecute | UnixFileMode.OtherRead |
                    UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
                Assert.Equal(UnixFileMode.None, mode & forbidden);
            }
        }

        // These adapters are the SAME production implementations used by
        // the operator workflow; only the hardcoded loopback CI realm is new.
        var verifiedSource = new OidcAccessTokenVerifier(Issuer, permitLocalDevelopmentHttp: true);
        using var live = new KeycloakTokenIntrospector(Issuer, allowLocalHttp: true,
            "temporalmark-mfa-identity-introspector", "local-mfa-introspect-only");
        using var directory = new KeycloakCurrentAccountDirectory(Issuer, allowLocalHttp: true,
            "temporalmark-mfa-directory-checker", "local-mfa-directory-only");
        var policy = new RegistrarIdentityGatePolicy(Issuer,
            "temporalmark-credential-registrar", "temporalmark-approval",
            "urn:temporalmark:loa:2", allowDisposableMfaCiLoopbackHttp: true);
        var gate = new ReviewerCredentialRegistrarIdentityGate(
            verifiedSource, live, directory, policy);
        var registrar = await File.ReadAllTextAsync(registrarPath!);
        var reviewer = await File.ReadAllTextAsync(reviewerPath!);
        var scope = new RegistrarRegistrationIdentityScope(ReviewerSubject,
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000003");

        // Before testing CURRENT-role revocation, assert that BOTH unchanged
        // access tokens still have a valid Keycloak signature, pinned audience
        // and a RECENT strong signed ACR. Otherwise mere expiry could cause a
        // false-positive negative test that never exercises authorization.
        var registrarSigned = await verifiedSource.VerifyAsync(registrar,
            "temporalmark-credential-registrar", CancellationToken.None);
        var reviewerSigned = await verifiedSource.VerifyAsync(reviewer,
            "temporalmark-approval", CancellationToken.None);
        var strong = new ApprovalAuthenticationPolicy(
            "urn:temporalmark:loa:2", TimeSpan.FromSeconds(120),
            allowPasswordOnlyDisposableLocalFixture: false);
        Assert.Equal("OIDC_ACR_ASSERTED", strong.Require(registrarSigned).Kind);
        Assert.Equal("OIDC_ACR_ASSERTED", strong.Require(reviewerSigned).Kind);
        Assert.Equal(RegistrarSubject, registrarSigned.Subject);
        Assert.Equal(ReviewerSubject, reviewerSigned.Subject);

        if (Environment.GetEnvironmentVariable("TEMPORALMARK_CI_REGISTRAR_EXPECT_DENIAL") == "true")
        {
            // Used after deleting the effective role or disabling the user
            // in Keycloak Admin REST, *without replacing the bearer tokens*.
            // A still-signed JWT MUST NOT override current live authorization.
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                gate.CheckAsync(registrar, reviewer, scope, CancellationToken.None));
            return;
        }

        var result = await gate.CheckAsync(registrar, reviewer, scope, CancellationToken.None);
        Assert.Equal(Issuer, result.Issuer);
        Assert.Equal(RegistrarSubject, result.RegistrarSubject);
        Assert.Equal(ReviewerSubject, result.ReviewerSubject);
        Assert.True(result.RegistrarAuthenticationTimeUnix > 0);
        Assert.True(result.ReviewerAuthenticationTimeUnix > 0);

        // Cross-audience swapping is prohibited even when both identities
        // have actually performed separate second factors in a real browser.
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            gate.CheckAsync(reviewer, registrar, scope, CancellationToken.None));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            gate.CheckAsync(registrar, registrar, scope, CancellationToken.None));
    }
}
