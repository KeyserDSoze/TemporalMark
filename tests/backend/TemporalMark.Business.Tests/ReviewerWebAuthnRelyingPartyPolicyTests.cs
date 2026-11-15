using TemporalMark.Business.Tenancy;
using Xunit;

namespace TemporalMark.Business.Tests;

/// <summary>
/// RED-first security contract for a future WebAuthn verifier.
/// An exact, server-approved RP/origin pair is necessary but NEVER sufficient
/// to prove user consent, authenticator possession, or a signed decision.
/// </summary>
public sealed class ReviewerWebAuthnRelyingPartyPolicyTests
{
    [Fact]
    public void PinsAnExplicitCanonicalHttpsOriginAndExactRpHost()
    {
        var policy = new ReviewerWebAuthnRelyingPartyPolicy(
            "review.example.org", "https://review.example.org");

        Assert.Equal("review.example.org", policy.RelyingPartyId);
        Assert.Equal("https://review.example.org", policy.TrustedOrigin);
        Assert.True(policy.MatchesDeclaredScope(
            "https://review.example.org", "review.example.org"));
    }

    [Fact]
    public void ExplicitHttpsPortIsPartOfThePinnedOrigin()
    {
        var policy = new ReviewerWebAuthnRelyingPartyPolicy(
            "review.example.org", "https://review.example.org:8443");

        Assert.True(policy.MatchesDeclaredScope(
            "https://review.example.org:8443", "review.example.org"));
        Assert.False(policy.MatchesDeclaredScope(
            "https://review.example.org", "review.example.org"));
        Assert.False(policy.MatchesDeclaredScope(
            "https://review.example.org:8444", "review.example.org"));
    }

    [Theory]
    [InlineData("http://review.example.org")]
    [InlineData("https://review.example.org.attacker.test")]
    [InlineData("https://review.example.org@attacker.test")]
    [InlineData("https://attacker.test")]
    [InlineData("https://review.example.org/path")]
    [InlineData("https://review.example.org?continue=1")]
    [InlineData("https://review.example.org#fragment")]
    [InlineData("https://review.example.org/")]
    [InlineData("https://review.example.org.")]
    [InlineData("https://REVIEW.example.org")]
    [InlineData("https://*.example.org")]
    [InlineData("https://localhost")]
    [InlineData("https://127.0.0.1")]
    [InlineData("https://[::1]")]
    [InlineData("https://review.example.org:443")]
    [InlineData("https://review.example.org:8443/anything")]
    [InlineData("")]
    public void FailsClosedForUntrustedOrNonCanonicalConfiguredOrigins(string origin)
    {
        Assert.Throws<ArgumentException>(() =>
            new ReviewerWebAuthnRelyingPartyPolicy("review.example.org", origin));
    }

    [Theory]
    [InlineData("example.org")]
    [InlineData("org")]
    [InlineData("*.example.org")]
    [InlineData("review.example.org.")]
    [InlineData("REVIEW.example.org")]
    [InlineData("review.example.org:443")]
    [InlineData("attacker.test")]
    [InlineData("localhost")]
    [InlineData("")]
    public void RejectsRelyingPartyIdNotEqualToTheServerTrustedOriginHost(string rpId)
    {
        Assert.Throws<ArgumentException>(() =>
            new ReviewerWebAuthnRelyingPartyPolicy(rpId, "https://review.example.org"));
    }

    [Theory]
    [InlineData("http://review.example.org", "review.example.org")]
    [InlineData("https://review.example.org.attacker.test", "review.example.org")]
    [InlineData("https://attacker.test", "review.example.org")]
    [InlineData("https://review.example.org", "attacker.test")]
    [InlineData("https://sub.review.example.org", "review.example.org")]
    [InlineData("https://review.example.org:8443", "review.example.org")]
    [InlineData("https://REVIEW.example.org", "review.example.org")]
    [InlineData("https://review.example.org", "REVIEW.example.org")]
    [InlineData(null, "review.example.org")]
    [InlineData("https://review.example.org", null)]
    [InlineData("", "review.example.org")]
    [InlineData("https://review.example.org", "")]
    public void UntrustedAssertionValuesCannotChangeThePinnedScope(
        string? suppliedOrigin, string? suppliedRpId)
    {
        var policy = new ReviewerWebAuthnRelyingPartyPolicy(
            "review.example.org", "https://review.example.org");

        Assert.False(policy.MatchesDeclaredScope(suppliedOrigin, suppliedRpId));
    }
}
