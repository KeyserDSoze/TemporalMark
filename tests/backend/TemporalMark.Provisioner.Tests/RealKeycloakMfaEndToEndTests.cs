using TemporalMark.Business.Tenancy;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// Live disposable-Keycloak browser MFA test, executed ONLY after Playwright
/// has performed a real password + OTP authorization-code/PKCE login.
/// No raw bearer tokens or OTP seeds appear in xUnit output.
/// </summary>
public sealed class RealKeycloakMfaEndToEndTests
{
    [Fact]
    public async Task BrowserOtpTokenPassesActualDotnetSignatureAndAcrPolicy()
    {
        var file = Environment.GetEnvironmentVariable("TEMPORALMARK_CI_MFA_TOKEN_FILE");
        // Normal developer-only unit suites have no Keycloak. CI invokes this
        // test a second time with the ephemeral token path explicitly set.
        if (string.IsNullOrEmpty(file)) return;

        Assert.True(File.Exists(file), "Browser OTP must produce the ephemeral signed token.");
        if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            var mode = File.GetUnixFileMode(file);
            const UnixFileMode forbidden = UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
                UnixFileMode.OtherExecute;
            Assert.Equal(UnixFileMode.None, mode & forbidden);
        }

        const string issuer = "http://localhost:8081/realms/temporalmark-mfa-ci";
        var verifier = new OidcAccessTokenVerifier(issuer, allowLocalHttp: true);
        var verified = await verifier.VerifyAsync(
            await File.ReadAllTextAsync(file), "temporalmark-approval", CancellationToken.None);

        Assert.Equal(issuer, verified.Issuer);
        Assert.Equal("00000000-0000-0000-0000-000000000034", verified.Subject);
        Assert.Contains("platform_approver", verified.Roles);
        // This is the production policy path: the localhost password-grant
        // exception is NOT used and cannot match the dedicated MFA realm.
        var policy = new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2",
            TimeSpan.FromSeconds(120), allowPasswordOnlyDisposableLocalFixture: false);
        var assurance = policy.Require(verified);
        Assert.Equal("OIDC_ACR_ASSERTED", assurance.Kind);
        Assert.Equal("urn:temporalmark:loa:2", assurance.Context);
        Assert.NotNull(assurance.AuthenticationTimeUnix);
        Assert.Equal("pinned-oidc-acr-v1", assurance.PolicyId);
    }
}
