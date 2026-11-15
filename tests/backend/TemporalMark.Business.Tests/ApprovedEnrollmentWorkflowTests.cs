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
        public Task<Guid> CompleteAsync(VerifiedOrganizationEnrollment input, CancellationToken ct)
        {
            Completions.Add(input);
            return Task.FromResult(input.OrganizationId);
        }
    }
}
