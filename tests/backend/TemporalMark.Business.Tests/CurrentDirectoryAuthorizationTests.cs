using TemporalMark.Business.Tenancy;
using Xunit;

namespace TemporalMark.Business.Tests;

public sealed class CurrentDirectoryAuthorizationTests
{
    private const string Issuer = "https://issuer.example.test/realm";
    private static readonly ProvisioningPolicy Policy = new(Issuer, "provisioning-api", "temporalmark-api");

    [Fact]
    public async Task MustQueryCurrentDirectoryForBothBeforeRequestAndCompleteAndApproverBeforeApproval()
    {
        var directory = new Directory();
        var storage = new Storage();
        var workflow = new OrganizationApprovalWorkflow(
            new Tokens(), new Live(), directory, storage, Policy, "temporalmark-approval", new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        var id = await workflow.RequestAsync("Client", "op.jwt", "admin.jwt", default);
        await workflow.ApproveAsync(id, "Client", "admin-sub", "operator-sub", "review.jwt", default);
        await workflow.CompleteAsync(id, "Client", "op.jwt", "admin.jwt", default);
        Assert.Equal(["operator-sub", "admin-sub", "review-sub", "operator-sub", "admin-sub"], directory.Queried);
        Assert.Single(storage.Requests);
        Assert.Single(storage.Approvals);
        Assert.Single(storage.Completions);
    }

    [Theory]
    [InlineData("operator-disabled")]
    [InlineData("admin-disabled")]
    [InlineData("missing-current-admin-role")]
    [InlineData("mismatched-account-sub")]
    [InlineData("wrong-directory-issuer")]
    [InlineData("provider-outage")]
    public async Task StaleOrUntrustedDirectoryStateStopsRequestBeforeWrite(string failure)
    {
        var storage = new Storage();
        var workflow = new OrganizationApprovalWorkflow(
            new Tokens(), new Live(), new Directory(failure), storage, Policy, "temporalmark-approval", new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        await Assert.ThrowsAnyAsync<Exception>(() =>
            workflow.RequestAsync("Client", "op.jwt", "admin.jwt", default));
        Assert.Empty(storage.Requests);
    }

    [Theory]
    [InlineData("review-disabled")]
    [InlineData("missing-current-review-role")]
    [InlineData("mismatched-account-sub")]
    [InlineData("provider-outage")]
    public async Task ApproverRequiresIndependentCurrentDirectoryAuthorization(string failure)
    {
        var storage = new Storage();
        var workflow = new OrganizationApprovalWorkflow(
            new Tokens(), new Live(), new Directory(failure), storage, Policy, "temporalmark-approval", new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        await Assert.ThrowsAnyAsync<Exception>(() =>
            workflow.ApproveAsync(Guid.NewGuid(), "Client", "admin-sub", "operator-sub", "review.jwt", default));
        Assert.Empty(storage.Approvals);
    }

    [Fact]
    public async Task RemovingRoleAfterRequestBlocksCompletionEvenWhenJwtAndIntrospectionStillContainRole()
    {
        var storage = new Storage();
        var directory = new Directory();
        var workflow = new OrganizationApprovalWorkflow(
            new Tokens(), new Live(), directory, storage, Policy, "temporalmark-approval", new ApprovalAuthenticationPolicy("urn:temporalmark:loa:2", TimeSpan.FromSeconds(120)));
        var id = await workflow.RequestAsync("Client", "op.jwt", "admin.jwt", default);
        await workflow.ApproveAsync(id, "Client", "admin-sub", "operator-sub", "review.jwt", default);
        directory.CurrentAdminRoleRevoked = true;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            workflow.CompleteAsync(id, "Client", "op.jwt", "admin.jwt", default));
        Assert.Empty(storage.Completions);
    }

    private sealed class Tokens : IVerifiedOidcTokenSource
    {
        public Task<VerifiedOidcToken> VerifyAsync(string token, string audience, CancellationToken ct) =>
            (token, audience) switch
            {
                ("op.jwt", "provisioning-api") =>
                    Task.FromResult(new VerifiedOidcToken(Issuer, "operator-sub", ["platform_provisioner"])),
                ("admin.jwt", "temporalmark-api") =>
                    Task.FromResult(new VerifiedOidcToken(Issuer, "admin-sub", ["tenant_admin"])),
                ("review.jwt", "temporalmark-approval") =>
                    Task.FromResult(new VerifiedOidcToken(Issuer, "review-sub", ["platform_approver"],
                        "urn:temporalmark:loa:2", DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 20,
                        DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 10)),
                _ => throw new UnauthorizedAccessException("Bad JWT")
            };
    }

    private sealed class Live : ILiveOidcTokenStatus
    {
        public Task<LiveOidcTokenState> CheckAsync(string token, string audience, CancellationToken ct) =>
            Task.FromResult(new LiveOidcTokenState(true, Issuer,
                token == "op.jwt" ? "operator-sub" : token == "admin.jwt" ? "admin-sub" : "review-sub",
                [audience], [token == "op.jwt" ? "platform_provisioner" :
                    token == "admin.jwt" ? "tenant_admin" : "platform_approver"]));
    }

    private sealed class Directory(string failure = "") : ICurrentOidcAccountDirectory
    {
        public List<string> Queried { get; } = [];
        public bool CurrentAdminRoleRevoked { get; set; }
        public Task<CurrentOidcAccount> GetAccountAsync(string issuer, string subject, CancellationToken ct)
        {
            Queried.Add(subject);
            if (failure == "provider-outage") throw new InvalidOperationException("Directory unavailable");
            var role = subject == "operator-sub" ? "platform_provisioner" :
                subject == "admin-sub" ? "tenant_admin" : "platform_approver";
            return Task.FromResult(new CurrentOidcAccount(
                failure == "wrong-directory-issuer" ? "https://imposter.example.test" : issuer,
                failure == "mismatched-account-sub" ? "other-sub" : subject,
                !(failure == "operator-disabled" && subject == "operator-sub") &&
                !(failure == "admin-disabled" && subject == "admin-sub") &&
                !(failure == "review-disabled" && subject == "review-sub"),
                (CurrentAdminRoleRevoked && subject == "admin-sub") ||
                (failure == "missing-current-admin-role" && subject == "admin-sub") ||
                (failure == "missing-current-review-role" && subject == "review-sub")
                    ? [] : [role]));
        }
    }

    private sealed class Storage : IOrganizationApprovalStore
    {
        public List<VerifiedOrganizationEnrollment> Requests { get; } = [];
        public Task<PendingOrganizationReview?> ReadPendingReviewAsync(
            Guid requestId, string issuer, string reviewerSubject, CancellationToken ct) =>
            Task.FromResult<PendingOrganizationReview?>(null);
        public List<VerifiedOrganizationApproval> Approvals { get; } = [];
        public List<VerifiedOrganizationEnrollment> Completions { get; } = [];
        public Task<Guid> RequestAsync(VerifiedOrganizationEnrollment e, CancellationToken ct)
        {
            Requests.Add(e);
            return Task.FromResult(e.OrganizationId);
        }
        public Task<Guid> ApproveAsync(VerifiedOrganizationApproval e, CancellationToken ct)
        {
            Approvals.Add(e);
            return Task.FromResult(e.OrganizationId);
        }
        public Task<Guid> CompleteAsync(VerifiedOrganizationEnrollment e, CancellationToken ct)
        {
            Completions.Add(e);
            return Task.FromResult(e.OrganizationId);
        }
    }
}
