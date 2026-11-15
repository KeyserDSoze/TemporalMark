using TemporalMark.Business.Tenancy;
using Xunit;

namespace TemporalMark.Business.Tests;

public sealed class ApprovalAuthenticationPolicyTests
{
    private const string StrongAcr = "urn:temporalmark:loa:2";
    private const string Issuer = "https://identity.example.test/realms/company";
    private const string LocalIssuer = "http://localhost:8081/realms/temporalmark";
    private const string LocalApprover = "00000000-0000-0000-0000-000000000004";

    [Fact]
    public void RequiresSignedClaimsForRecentStrongAuthentication()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var policy = new ApprovalAuthenticationPolicy(StrongAcr, TimeSpan.FromSeconds(120));
        policy.Require(new VerifiedOidcToken(Issuer, "reviewer", ["platform_approver"],
            StrongAcr, now - 30, now - 20));
    }

    [Theory]
    [InlineData(null, -10, -5)]
    [InlineData("0", -10, -5)]
    [InlineData("1", -10, -5)]
    [InlineData("pwd", -10, -5)]
    [InlineData("urn:temporalmark:loa:2 ", -10, -5)]
    [InlineData("urn:temporalmark:loa:2", -125, -5)]
    [InlineData("urn:temporalmark:loa:2", 45, -5)]
    [InlineData("urn:temporalmark:loa:2", 0, -70)]
    public void DeniesMissingWeakMismatchedStaleFutureOrInconsistentEvidence(
        string? acr, int authTimeOffset, int issuedAtOffset)
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var policy = new ApprovalAuthenticationPolicy(StrongAcr, TimeSpan.FromSeconds(120));
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.Require(new VerifiedOidcToken(Issuer, "reviewer", ["platform_approver"],
                acr, now + authTimeOffset, now + issuedAtOffset)));
    }

    [Fact]
    public void DeniesAbsentAuthenticationTimeAndIssuedAt()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var policy = new ApprovalAuthenticationPolicy(StrongAcr, TimeSpan.FromSeconds(120));
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.Require(new VerifiedOidcToken(Issuer, "reviewer", ["platform_approver"],
                StrongAcr, null, now)));
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.Require(new VerifiedOidcToken(Issuer, "reviewer", ["platform_approver"],
                StrongAcr, now, null)));
    }

    [Theory]
    [InlineData("")]
    [InlineData("0")]
    [InlineData("1")]
    [InlineData("pwd")]
    [InlineData("password")]
    [InlineData("basic")]
    [InlineData(" urn:strong")]
    public void RefusesMissingOrKnownPasswordOnlyPolicyValues(string acr) =>
        Assert.Throws<ArgumentException>(() =>
            new ApprovalAuthenticationPolicy(acr, TimeSpan.FromSeconds(90)));

    [Theory]
    [InlineData(0)]
    [InlineData(121)]
    [InlineData(300)]
    public void RefusesUnsafeMaxAuthenticationAges(int seconds) =>
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ApprovalAuthenticationPolicy(StrongAcr, TimeSpan.FromSeconds(seconds)));

    [Fact]
    public void DisposablePasswordGrantExceptionIsRestrictedToKnownLoopbackRealmAndFixtureAccount()
    {
        var policy = new ApprovalAuthenticationPolicy(StrongAcr, TimeSpan.FromSeconds(90),
            allowPasswordOnlyDisposableLocalFixture: true);
        policy.Require(new VerifiedOidcToken(LocalIssuer, LocalApprover, ["platform_approver"]));
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.Require(new VerifiedOidcToken(Issuer, LocalApprover, ["platform_approver"])));
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.Require(new VerifiedOidcToken(LocalIssuer, "someone-else", ["platform_approver"])));
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.Require(new VerifiedOidcToken("http://127.0.0.1:8081/realms/temporalmark",
                LocalApprover, ["platform_approver"])));
    }

    [Fact]
    public void RealSignedAcrAndLocalNonMfaFixtureAreRecordedWithDistinctProvenance()
    {
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var normal = new ApprovalAuthenticationPolicy(StrongAcr, TimeSpan.FromSeconds(120));
        var verified = normal.Require(new VerifiedOidcToken(Issuer, "reviewer",
            ["platform_approver"], StrongAcr, now - 5, now - 3));
        Assert.Equal("OIDC_ACR_ASSERTED", verified.Kind);
        Assert.Equal(StrongAcr, verified.Context);
        Assert.Equal(now - 5, verified.AuthenticationTimeUnix);
        Assert.Equal("pinned-oidc-acr-v1", verified.PolicyId);

        var local = new ApprovalAuthenticationPolicy(StrongAcr, TimeSpan.FromSeconds(120),
            allowPasswordOnlyDisposableLocalFixture: true);
        var nonMfa = local.Require(new VerifiedOidcToken(LocalIssuer, LocalApprover,
            ["platform_approver"], StrongAcr, now - 5, now - 3));
        Assert.Equal("DISPOSABLE_PASSWORD_ONLY", nonMfa.Kind);
        Assert.Null(nonMfa.Context);
        Assert.Null(nonMfa.AuthenticationTimeUnix);
        Assert.Equal("disposable-keycloak-pilot-v1", nonMfa.PolicyId);
    }

    [Fact]
    public void FixtureExceptionIsNeverAutomatic()
    {
        var policy = new ApprovalAuthenticationPolicy(StrongAcr, TimeSpan.FromSeconds(90));
        Assert.Throws<UnauthorizedAccessException>(() =>
            policy.Require(new VerifiedOidcToken(LocalIssuer, LocalApprover, ["platform_approver"])));
    }
}
