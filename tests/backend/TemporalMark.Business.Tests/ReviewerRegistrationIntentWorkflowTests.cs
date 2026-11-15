using TemporalMark.Business.Tenancy;
using Xunit;

namespace TemporalMark.Business.Tests;

/// <summary>
/// RED first: an issued nonce is NEVER trusted WebAuthn credential registration,
/// attestation or a signed reviewer decision. Only the concrete signed+live+
/// current-directory gate may precede the restricted intent store.
/// </summary>
public sealed class ReviewerRegistrationIntentWorkflowTests
{
    private const string Issuer = "https://identity.example.org/realms/registrar";
    private const string Rp = "review.example.org";
    private const string Origin = "https://review.example.org";
    private const string RegistrarAudience = "temporalmark-credential-registrar";
    private const string ReviewerAudience = "temporalmark-approval";
    private const string Acr = "urn:temporalmark:loa:2";
    private const string RegistrarSub = "registrar-sub";
    private const string ReviewerSub = "reviewer-sub";

    private static ReviewerRegistrationIntentWorkflow Create(
        IntentStore store, string failure = "")
    {
        var gate = new ReviewerCredentialRegistrarIdentityGate(
            new Signed(failure), new Live(failure), new Directory(failure),
            new RegistrarIdentityGatePolicy(Issuer, RegistrarAudience, ReviewerAudience, Acr));
        return new ReviewerRegistrationIntentWorkflow(gate, store,
            new RegistrarIntentDeploymentPolicy(Issuer, Rp, Origin, ReviewerSub));
    }

    [Fact]
    public async Task DualValidPrincipalsCreateOneOnlyUnconsumableAndExactlyBoundIntent()
    {
        var store = new IntentStore();
        var result = await Create(store).IssueAsync("registrar.jwt", "reviewer.jwt", default);
        Assert.Single(store.Issued);
        var sent = store.Issued.Single();
        Assert.Equal(Issuer, sent.IdentityIssuer);
        Assert.Equal(RegistrarSub, sent.RegistrarSubject);
        Assert.Equal(ReviewerSub, sent.ReviewerSubject);
        Assert.Equal(Rp, sent.RelyingPartyId);
        Assert.Equal(Origin, sent.TrustedOrigin);
        Assert.NotEqual(Guid.Empty, result.IntentId);
        Assert.Matches("^[0-9A-F]{96}$", result.ChallengeHex);
        Assert.Equal(RegistrarSub, result.RegistrarSubject);
        Assert.Equal(ReviewerSub, result.ReviewerSubject);
        Assert.Equal(Issuer, result.IdentityIssuer);
        Assert.Equal(Rp, result.RelyingPartyId);
        Assert.Equal(Origin, result.TrustedOrigin);
    }

    [Theory]
    [InlineData("forged-registrar")]
    [InlineData("forged-reviewer")]
    [InlineData("wrong-audience")]
    [InlineData("wrong-registrar-role")]
    [InlineData("wrong-reviewer-role")]
    [InlineData("inactive-registrar")]
    [InlineData("inactive-reviewer")]
    [InlineData("revoked-registrar-role")]
    [InlineData("revoked-reviewer-role")]
    [InlineData("disabled-registrar")]
    [InlineData("disabled-reviewer")]
    [InlineData("network-outage")]
    [InlineData("wrong-issuer")]
    public async Task NoDbWriteWhenPrincipalNotSignedLiveOrCurrentlyAuthorized(string failure)
    {
        var store = new IntentStore();
        await Assert.ThrowsAnyAsync<Exception>(() =>
            Create(store, failure).IssueAsync("registrar.jwt", "reviewer.jwt", default));
        Assert.Empty(store.Issued);
    }

    [Fact]
    public async Task RejectsSameBearerWithoutAnyCallToStore()
    {
        var store = new IntentStore();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Create(store).IssueAsync("registrar.jwt", "registrar.jwt", default));
        Assert.Empty(store.Issued);
    }

    [Theory]
    [InlineData("http://identity.example.org/realms/registrar", Rp, Origin, ReviewerSub)]
    [InlineData(Issuer, "other.example.org", Origin, ReviewerSub)]
    [InlineData(Issuer, Rp, "https://review.example.org:444", ReviewerSub)]
    [InlineData(Issuer, Rp, "http://review.example.org", ReviewerSub)]
    [InlineData(Issuer, "127.0.0.1", "https://127.0.0.1", ReviewerSub)]
    [InlineData(Issuer, Rp, Origin, " reviewer-sub")]
    [InlineData(Issuer, Rp, Origin, "")]
    public void NeverTrustCallerChosenPolicyOrReviewer(
        string issuer, string rp, string origin, string reviewer)
    {
        Assert.Throws<ArgumentException>(() =>
            new RegistrarIntentDeploymentPolicy(issuer, rp, origin, reviewer));
    }

    [Theory]
    [InlineData("wrong-hex-length")]
    [InlineData("lowercase-hex")]
    [InlineData("expired")]
    [InlineData("overlong-ttl")]
    [InlineData("missing-uuid")]
    [InlineData("future-issued")]
    public async Task InvalidSqlIssuedMetadataCannotBeReturnedAsIntent(string failure)
    {
        var store = new IntentStore { BadResult = failure };
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Create(store).IssueAsync("registrar.jwt", "reviewer.jwt", default));
        Assert.Single(store.Issued);
    }

    [Fact]
    public async Task SqlOneEverConflictIsNotSilentlyRetryable()
    {
        var store = new IntentStore { BadResult = "duplicate" };
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Create(store).IssueAsync("registrar.jwt", "reviewer.jwt", default));
        Assert.Single(store.Issued);
    }

    private sealed class IntentStore : IReviewerRegistrationIntentStore
    {
        public List<PreflightedRegistrarRegistrationIntent> Issued { get; } = [];
        public string? BadResult { get; init; }

        public Task<RegistrarIntentStorageResult> IssueAsync(
            PreflightedRegistrarRegistrationIntent request, CancellationToken ct)
        {
            Issued.Add(request);
            if (BadResult == "duplicate") throw new InvalidOperationException("One-ever unique conflict");
            var now = DateTimeOffset.UtcNow;
            var id = Guid.NewGuid();
            var hex = new string('A', 96);
            var expires = now.AddMinutes(2);
            if (BadResult == "wrong-hex-length") hex = "AA";
            if (BadResult == "lowercase-hex") hex = new string('a', 96);
            if (BadResult == "expired") expires = now.AddSeconds(-1);
            if (BadResult == "overlong-ttl") expires = now.AddMinutes(3);
            if (BadResult == "missing-uuid") id = Guid.Empty;
            if (BadResult == "future-issued") now = now.AddMinutes(20);
            return Task.FromResult(new RegistrarIntentStorageResult(id, hex, now, expires));
        }
    }

    private sealed class Signed(string failure) : IVerifiedOidcTokenSource
    {
        public Task<VerifiedOidcToken> VerifyAsync(string token, string audience, CancellationToken ct)
        {
            var reg = token == "registrar.jwt";
            if (failure == (reg ? "forged-registrar" : "forged-reviewer") ||
                failure == "wrong-audience" && reg ||
                audience != (reg ? RegistrarAudience : ReviewerAudience))
                throw new UnauthorizedAccessException("Invalid signature/audience");
            var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            return Task.FromResult(new VerifiedOidcToken(
                failure == "wrong-issuer" ? "https://malicious.example.org" : Issuer,
                reg ? RegistrarSub : ReviewerSub,
                [failure == (reg ? "wrong-registrar-role" : "wrong-reviewer-role")
                    ? "unrelated" : reg ? "platform_credential_registrar" : "platform_approver"],
                Acr, now - 20, now - 10));
        }
    }

    private sealed class Live(string failure) : ILiveOidcTokenStatus
    {
        public Task<LiveOidcTokenState> CheckAsync(string token, string audience, CancellationToken ct)
        {
            if (failure == "network-outage") throw new HttpRequestException("IdP offline");
            var reg = token == "registrar.jwt";
            return Task.FromResult(new LiveOidcTokenState(
                failure != (reg ? "inactive-registrar" : "inactive-reviewer"),
                Issuer, reg ? RegistrarSub : ReviewerSub, [audience],
                [reg ? "platform_credential_registrar" : "platform_approver"]));
        }
    }

    private sealed class Directory(string failure) : ICurrentOidcAccountDirectory
    {
        public Task<CurrentOidcAccount> GetAccountAsync(string issuer, string subject, CancellationToken ct)
        {
            var reg = subject == RegistrarSub;
            return Task.FromResult(new CurrentOidcAccount(Issuer, subject,
                failure != (reg ? "disabled-registrar" : "disabled-reviewer"),
                [failure == (reg ? "revoked-registrar-role" : "revoked-reviewer-role")
                    ? "removed-role" : reg ? "platform_credential_registrar" : "platform_approver"]));
        }
    }
}
