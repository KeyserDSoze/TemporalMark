using TemporalMark.Business.Tenancy;
using Xunit;

namespace TemporalMark.Business.Tests;

public sealed class ApprovedEnrollmentWorkflowTests
{
    private const string Issuer = "https://issuer.example.test/realm";
    private static readonly ProvisioningPolicy Policy = new(Issuer, "provisioning-api", "temporalmark-api");
    private const string ApprovalAudience = "temporalmark-approval";

    [Fact]
    public async Task RequestDoesNotCreateOrganizationAndApprovalIsSeparate()
    {
        var store = new PendingStore();
        var flow = new OrganizationApprovalWorkflow(new Tokens(), new Live(), new Directory(), store, Policy, ApprovalAudience, new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        var request = await flow.RequestAsync("Reviewed Organization", "op.jwt", "admin.jwt", default);
        Assert.NotEqual(Guid.Empty, request);
        Assert.Single(store.Requests);
        Assert.Empty(store.Completions);
        Assert.Equal(request, store.Requests[0].OrganizationId);
        Assert.Equal("operator-sub", store.Requests[0].ProvisionerSubject);
        Assert.Equal("admin-sub", store.Requests[0].FirstAdminSubject);
        Assert.Equal(Issuer, store.Requests[0].IdentityIssuer);

        await flow.ApproveAsync(request, "Reviewed Organization", "admin-sub", "operator-sub",
            "approver.jwt", default);
        Assert.Single(store.Approvals);
        Assert.Equal("approver-sub", store.Approvals[0].ApproverSubject);
        Assert.Equal("admin-sub", store.Approvals[0].ExpectedAdminSubject);
        Assert.Equal("operator-sub", store.Approvals[0].ExpectedOperatorSubject);
        // Signed authentication provenance must travel to durable approval storage.
        Assert.Equal("OIDC_ACR_ASSERTED", store.Approvals[0].AuthenticationEvidence.Kind);
        Assert.Equal("urn:temporalmark:loa:2", store.Approvals[0].AuthenticationEvidence.Context);
        Assert.InRange(store.Approvals[0].AuthenticationEvidence.AuthenticationTimeUnix!.Value,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 120,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        Assert.Equal("pinned-oidc-acr-v1", store.Approvals[0].AuthenticationEvidence.PolicyId);
        Assert.Equal(request, await flow.CompleteAsync(
            request, "Reviewed Organization", "op.jwt", "admin.jwt", default));
        Assert.Single(store.Completions);
    }

    [Fact]
    public async Task ReviewerGetsOriginalDatabaseScopeAndApproveRequiresExactReviewDigest()
    {
        var store = new PendingStore();
        var flow = new OrganizationApprovalWorkflow(new Tokens(), new Live(), new Directory(),
            store, Policy, ApprovalAudience,
            new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        var id = await flow.RequestAsync("Original Legal Entity", "op.jwt", "admin.jwt", default);
        var review = await flow.ReviewAsync(id, "approver.jwt", default);
        Assert.Equal(id, review.RequestId);
        Assert.Equal("Original Legal Entity", review.OrganizationName);
        Assert.Equal(Issuer, review.IdentityIssuer);
        Assert.Equal("operator-sub", review.OperatorSubject);
        Assert.Equal("admin-sub", review.FirstAdminSubject);
        Assert.Matches("^[0-9A-F]{64}$", review.ReviewSha256);
        Assert.Empty(store.Approvals);
        Assert.Empty(store.Completions);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            flow.ApproveReviewedAsync(id, new string('0', 64), "approver.jwt", default));
        Assert.Empty(store.Approvals);
        Assert.Equal(id, await flow.ApproveReviewedAsync(id, review.ReviewSha256, "approver.jwt", default));
        Assert.Single(store.Approvals);
        Assert.Equal("Original Legal Entity", store.Approvals[0].ExpectedOrganizationName);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            flow.ReviewAsync(id, "approver.jwt", default));
    }

    [Fact]
    public void CanonicalDigestIsBoundToEveryOriginalFieldAndExpiry()
    {
        var id = Guid.NewGuid();
        var expiry = DateTimeOffset.UtcNow.AddMinutes(3);
        var scope = new PendingOrganizationReview(id, "Legal Name", Issuer, "operator-sub",
            "admin-sub", expiry);
        Assert.Equal(scope.ReviewSha256, new PendingOrganizationReview(id, "Legal Name",
            Issuer, "operator-sub", "admin-sub", expiry).ReviewSha256);
        Assert.NotEqual(scope.ReviewSha256, (scope with { OrganizationName = "Changed Legal Name" }).ReviewSha256);
        Assert.NotEqual(scope.ReviewSha256, (scope with { OperatorSubject = "another" }).ReviewSha256);
        Assert.NotEqual(scope.ReviewSha256, (scope with { FirstAdminSubject = "another" }).ReviewSha256);
        Assert.NotEqual(scope.ReviewSha256, (scope with { IdentityIssuer = "https://wrong.example" }).ReviewSha256);
        Assert.NotEqual(scope.ReviewSha256, (scope with { ExpiresUtc = expiry.AddSeconds(1) }).ReviewSha256);
        Assert.NotEqual(scope.ReviewSha256, (scope with { RequestId = Guid.NewGuid() }).ReviewSha256);
    }

    [Fact]
    public async Task NoReviewerCanReadAnUnauthorizedExpiredOrChangedScope()
    {
        var store = new PendingStore();
        var flow = new OrganizationApprovalWorkflow(new Tokens(), new Live(), new Directory(),
            store, Policy, ApprovalAudience,
            new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        var id = await flow.RequestAsync("Original", "op.jwt", "admin.jwt", default);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            flow.ReviewAsync(id, "operator-approver.jwt", default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            flow.ReviewAsync(id, "unsigned.jwt", default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            flow.ReviewAsync(Guid.NewGuid(), "approver.jwt", default));
        store.Expired = true;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            flow.ReviewAsync(id, "approver.jwt", default));
        Assert.Empty(store.Approvals);
    }

    [Fact]
    public async Task ReviewerCanRejectOnlyTheOriginallyReviewedScopeOnce()
    {
        var store = new PendingStore();
        var workflow = new OrganizationApprovalWorkflow(new Tokens(), new Live(), new Directory(),
            store, Policy, ApprovalAudience,
            new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        var id = await workflow.RequestAsync("Real Legal Organization", "op.jwt", "admin.jwt", default);
        var review = await workflow.ReviewAsync(id, "approver.jwt", default);

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            workflow.RejectReviewedAsync(id, new string('A', 64), "UNVERIFIED_IDENTITY",
                "approver.jwt", default));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            workflow.RejectReviewedAsync(id, review.ReviewSha256, "Freeform private reason",
                "approver.jwt", default));
        Assert.Empty(store.Rejections);

        Assert.Equal(id, await workflow.RejectReviewedAsync(id, review.ReviewSha256,
            "UNVERIFIED_IDENTITY", "approver.jwt", default));
        Assert.Single(store.Rejections);
        Assert.Equal("Real Legal Organization", store.Rejections[0].ExpectedOrganizationName);
        Assert.Equal(review.ReviewSha256, store.Rejections[0].ReviewSha256);
        Assert.Equal("UNVERIFIED_IDENTITY", store.Rejections[0].ReasonCode);
        Assert.Equal("approver-sub", store.Rejections[0].ReviewerSubject);
        Assert.Matches("^[0-9A-F]{64}$", store.Rejections[0].ReviewerProofHashHex);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            workflow.ReviewAsync(id, "approver.jwt", default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            workflow.ApproveReviewedAsync(id, review.ReviewSha256, "approver.jwt", default));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            workflow.RejectReviewedAsync(id, review.ReviewSha256,
                "UNVERIFIED_IDENTITY", "approver.jwt", default));
        Assert.Empty(store.Approvals);
    }

    [Theory]
    [InlineData("unprivileged.jwt")]
    [InlineData("unsigned.jwt")]
    [InlineData("operator-approver.jwt")]
    public async Task UnauthorizedRejectionCannotPersistAnything(string token)
    {
        var store = new PendingStore();
        var workflow = new OrganizationApprovalWorkflow(new Tokens(), new Live(), new Directory(),
            store, Policy, ApprovalAudience,
            new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        var id = await workflow.RequestAsync("Deny Unauthorized", "op.jwt", "admin.jwt", default);
        var review = await workflow.ReviewAsync(id, "approver.jwt", default);
        await Assert.ThrowsAnyAsync<Exception>(() =>
            workflow.RejectReviewedAsync(id, review.ReviewSha256,
                "UNVERIFIED_ORGANIZATION", token, default));
        Assert.Empty(store.Rejections);
    }

    [Fact]
    public async Task AuthenticatedReviewerCanIssueDecisionChallengeWithoutApproving()
    {
        var storage = new PendingStore();
        var flow = new OrganizationApprovalWorkflow(new Tokens(),new Live(),new Directory(),
            storage,Policy,ApprovalAudience,
            new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2",TimeSpan.FromSeconds(120)));
        var id=await flow.RequestAsync("Exact Legal Name","op.jwt","admin.jwt",default);
        var review=await flow.ReviewAsync(id,"approver.jwt",default);
        var result=await flow.IssueDecisionChallengeAsync(id,review.ReviewSha256,
            "APPROVE",null,"approver.jwt",default);
        Assert.Equal(id,result.RequestId);
        Assert.Equal(review.ReviewSha256,result.ReviewSha256);
        Assert.Equal("APPROVE",result.Decision);
        Assert.Null(result.ReasonCode);
        Assert.Equal("approver-sub",result.ReviewerSubject);
        Assert.Matches("^[0-9A-F]{96}$",result.ChallengeHex);
        Assert.True(result.ExpiresUtc>result.IssuedUtc);
        Assert.True(result.ExpiresUtc<=review.ExpiresUtc);
        Assert.InRange(result.ExpiresUtc-result.IssuedUtc,
            TimeSpan.FromSeconds(1),TimeSpan.FromSeconds(60));
        Assert.Single(storage.Challenges);
        Assert.Empty(storage.Approvals);
        Assert.Empty(storage.Rejections);
        Assert.Empty(storage.Completions);
    }

    [Theory]
    [InlineData("APPROVE","UNVERIFIED_IDENTITY")]
    [InlineData("REJECT",null)]
    [InlineData("REJECT","freeform reason")]
    [InlineData("APPROVE_ME",null)]
    public async Task InvalidChallengeDecisionOrReasonNeverWrites(
        string decision,string? reason)
    {
        var storage=new PendingStore();
        var flow=new OrganizationApprovalWorkflow(new Tokens(),new Live(),new Directory(),
            storage,Policy,ApprovalAudience,
            new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2",TimeSpan.FromSeconds(120)));
        var id=await flow.RequestAsync("Organization","op.jwt","admin.jwt",default);
        var review=await flow.ReviewAsync(id,"approver.jwt",default);
        await Assert.ThrowsAsync<ArgumentException>(()=>
            flow.IssueDecisionChallengeAsync(id,review.ReviewSha256,decision,reason,
                "approver.jwt",default));
        Assert.Empty(storage.Challenges);
    }

    [Fact]
    public async Task ChallengeRequiresFreshDbReviewAndSignedCurrentReviewer()
    {
        var storage=new PendingStore();
        var flow=new OrganizationApprovalWorkflow(new Tokens(),new Live(),new Directory(),
            storage,Policy,ApprovalAudience,
            new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2",TimeSpan.FromSeconds(120)));
        var id=await flow.RequestAsync("Organization","op.jwt","admin.jwt",default);
        var review=await flow.ReviewAsync(id,"approver.jwt",default);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>
            flow.IssueDecisionChallengeAsync(id,new string('A',64),"REJECT",
                "UNVERIFIED_ORGANIZATION","approver.jwt",default));
        await Assert.ThrowsAnyAsync<Exception>(()=>
            flow.IssueDecisionChallengeAsync(id,review.ReviewSha256,"APPROVE",
                null,"unprivileged.jwt",default));
        await Assert.ThrowsAnyAsync<Exception>(()=>
            flow.IssueDecisionChallengeAsync(id,review.ReviewSha256,"APPROVE",
                null,"operator-approver.jwt",default));
        storage.Expired=true;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(()=>
            flow.IssueDecisionChallengeAsync(id,review.ReviewSha256,"APPROVE",
                null,"approver.jwt",default));
        Assert.Empty(storage.Challenges);
    }

    [Theory]
    [InlineData("missing-role")]
    [InlineData("same-identity")]
    [InlineData("bad-issuer")]
    [InlineData("disabled")]
    [InlineData("outage")]
    [InlineData("unsigned")]
    public async Task RejectsUnauthorizedApproverWithoutWriting(string reason)
    {
        var store = new PendingStore();
        var flow = new OrganizationApprovalWorkflow(new Tokens(), new Live(reason), new Directory(), store, Policy, ApprovalAudience, new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        var id = Guid.NewGuid();
        var token = reason == "missing-role" ? "unprivileged.jwt" :
            reason == "same-identity" ? "operator-approver.jwt" :
            reason == "bad-issuer" ? "alien.jwt" :
            reason == "unsigned" ? "unsigned.jwt" : "approver.jwt";
        await Assert.ThrowsAnyAsync<Exception>(() =>
            flow.ApproveAsync(id, "Client", "admin-sub", "operator-sub", token, default));
        Assert.Empty(store.Approvals);
        Assert.Empty(store.Completions);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(" Trailing")]
    [InlineData("Unsafe\nName")]
    public async Task RejectsInvalidApprovalScopeBeforeIdpRequest(string name)
    {
        var live = new Live();
        var store = new PendingStore();
        var flow = new OrganizationApprovalWorkflow(new Tokens(), live, new Directory(), store, Policy, ApprovalAudience, new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            flow.ApproveAsync(Guid.NewGuid(), name, "admin-sub", "operator-sub", "approver.jwt", default));
        Assert.Empty(live.Checked);
        Assert.Empty(store.Approvals);
    }

    [Fact]
    public async Task AnyLiveIdentityFailureOnCompletePreventsDatabaseWrite()
    {
        var store = new PendingStore();
        var flow = new OrganizationApprovalWorkflow(new Tokens(), new Live("disabled-admin"), new Directory(), store, Policy, ApprovalAudience, new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            flow.CompleteAsync(Guid.NewGuid(), "Client", "op.jwt", "admin.jwt", default));
        Assert.Empty(store.Completions);
    }

    private sealed class Tokens : IVerifiedOidcTokenSource
    {
        public Task<VerifiedOidcToken> VerifyAsync(string token, string audience, CancellationToken ct) =>
            (token, audience) switch
            {
                ("op.jwt", "provisioning-api") => Task.FromResult(new VerifiedOidcToken(Issuer, "operator-sub", ["platform_provisioner"])),
                ("admin.jwt", "temporalmark-api") => Task.FromResult(new VerifiedOidcToken(Issuer, "admin-sub", ["tenant_admin"])),
                ("approver.jwt", ApprovalAudience) => Task.FromResult(new VerifiedOidcToken(Issuer, "approver-sub", ["platform_approver"],
                        "urn:temporalmark:loa:2", DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 20,
                        DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 10)),
                ("unprivileged.jwt", ApprovalAudience) => Task.FromResult(new VerifiedOidcToken(Issuer, "approver-sub", [])),
                ("operator-approver.jwt", ApprovalAudience) => Task.FromResult(new VerifiedOidcToken(Issuer, "operator-sub", ["platform_approver"])),
                ("alien.jwt", ApprovalAudience) => Task.FromResult(new VerifiedOidcToken("https://alien.example.test", "approver-sub", ["platform_approver"])),
                _ => throw new UnauthorizedAccessException("Invalid signed OIDC proof")
            };
    }

    private sealed class Live(string reason = "") : ILiveOidcTokenStatus
    {
        public List<string> Checked { get; } = [];
        public Task<LiveOidcTokenState> CheckAsync(string token, string audience, CancellationToken ct)
        {
            Checked.Add(token);
            if (reason == "outage") throw new InvalidOperationException("Keycloak unavailable");
            var isOperator = token == "op.jwt";
            var isAdmin = token == "admin.jwt";
            return Task.FromResult(new LiveOidcTokenState(
                reason != "disabled" && !(reason == "disabled-admin" && isAdmin),
                Issuer,
                isOperator ? "operator-sub" : isAdmin ? "admin-sub" :
                    token == "operator-approver.jwt" ? "operator-sub" : "approver-sub",
                [audience],
                [isOperator ? "platform_provisioner" : isAdmin ? "tenant_admin" :
                    token == "unprivileged.jwt" ? "guest" : "platform_approver"]));
        }
    }

    private sealed class Directory : ICurrentOidcAccountDirectory
    {
        public Task<CurrentOidcAccount> GetAccountAsync(string issuer, string subject,
            CancellationToken ct) =>
            Task.FromResult(new CurrentOidcAccount(issuer, subject, true,
                subject == "operator-sub" ? ["platform_provisioner"] :
                subject == "admin-sub" ? ["tenant_admin"] : ["platform_approver"]));
    }

    private sealed class PendingStore : IOrganizationApprovalStore
    {
        public List<VerifiedOrganizationEnrollment> Requests { get; } = [];
        public bool Expired { get; set; }
        private readonly DateTimeOffset expiry = DateTimeOffset.UtcNow.AddMinutes(4);
        public Task<PendingOrganizationReview?> ReadPendingReviewAsync(
            Guid requestId, string issuer, string reviewerSubject, CancellationToken ct)
        {
            var input = Requests.SingleOrDefault(x => x.OrganizationId == requestId);
            if (input is null || input.IdentityIssuer != issuer || Expired ||
                input.ProvisionerSubject == reviewerSubject ||
                input.FirstAdminSubject == reviewerSubject ||
                Approvals.Any(x => x.OrganizationId == requestId) ||
                Rejections.Any(x => x.OrganizationId == requestId) ||
                Completions.Any(x => x.OrganizationId == requestId))
                return Task.FromResult<PendingOrganizationReview?>(null);
            return Task.FromResult<PendingOrganizationReview?>(
                new PendingOrganizationReview(input.OrganizationId, input.OrganizationName,
                    input.IdentityIssuer, input.ProvisionerSubject,
                    input.FirstAdminSubject, expiry));
        }
        public List<VerifiedOrganizationRejection> Rejections { get; } = [];
        public List<VerifiedReviewerDecisionChallengeRequest> Challenges { get; } = [];

        public List<VerifiedOrganizationApproval> Approvals { get; } = [];
        public List<VerifiedOrganizationEnrollment> Completions { get; } = [];

        public Task<Guid> RequestAsync(VerifiedOrganizationEnrollment input, CancellationToken ct)
        {
            Requests.Add(input);
            return Task.FromResult(input.OrganizationId);
        }
        public Task<Guid> ApproveAsync(VerifiedOrganizationApproval input, CancellationToken ct)
        {
            Approvals.Add(input);
            return Task.FromResult(input.OrganizationId);
        }
        public Task<IssuedReviewerDecisionChallenge> IssueDecisionChallengeAsync(
            VerifiedReviewerDecisionChallengeRequest request,CancellationToken ct)
        {
            if(Challenges.Any(x=>x.Scope.RequestId==request.Scope.RequestId))
                throw new UnauthorizedAccessException("Already challenged");
            Challenges.Add(request);
            var now=DateTimeOffset.UtcNow;
            return Task.FromResult(new IssuedReviewerDecisionChallenge(
                Guid.NewGuid(),request.Scope.RequestId,request.Scope.ReviewSha256,
                request.Scope.IdentityIssuer,request.ReviewerSubject,
                request.Decision,request.ReasonCode,new string('A',96),
                now,now.AddSeconds(45)));
        }

        public Task<Guid> RejectAsync(VerifiedOrganizationRejection input, CancellationToken ct)
        {
            if (Rejections.Any(x => x.OrganizationId == input.OrganizationId))
                throw new UnauthorizedAccessException("Already rejected.");
            Rejections.Add(input);
            return Task.FromResult(input.OrganizationId);
        }

        public Task<Guid> CompleteAsync(VerifiedOrganizationEnrollment input, CancellationToken ct)
        {
            Completions.Add(input);
            return Task.FromResult(input.OrganizationId);
        }
    }
}
