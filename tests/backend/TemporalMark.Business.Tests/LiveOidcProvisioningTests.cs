using TemporalMark.Business.Tenancy;
using Xunit;

namespace TemporalMark.Business.Tests;

public sealed class LiveOidcProvisioningTests
{
    private const string Issuer = "https://issuer.example.test/realm";
    private static readonly ProvisioningPolicy Policy = new(Issuer, "provisioning-api", "temporalmark-api");

    [Fact]
    public async Task TwoLiveStatusChecksMustSucceedBeforeAnyDatabaseWrite()
    {
        var store = new Store();
        var status = new LiveStatus();
        var service = new OrganizationProvisioningService(new SignedTokens(), status, store, Policy);
        await service.CreateAsync("Client", "operator.jwt", "admin.jwt", default);
        Assert.Equal(["operator.jwt", "admin.jwt"], status.Checked);
        Assert.Single(store.Saved);
    }

    [Theory]
    [InlineData("inactive-operator")]
    [InlineData("inactive-admin")]
    [InlineData("other-sub")]
    [InlineData("other-issuer")]
    [InlineData("wrong-audience")]
    [InlineData("missing-role")]
    [InlineData("status-outage")]
    public async Task NoOrganizationOnFailedLiveStatus(string caseName)
    {
        var store = new Store();
        var status = new LiveStatus(caseName);
        var service = new OrganizationProvisioningService(new SignedTokens(), status, store, Policy);
        await Assert.ThrowsAnyAsync<Exception>(() =>
            service.CreateAsync("Client", "operator.jwt", "admin.jwt", default));
        Assert.Empty(store.Saved);
    }

    [Fact]
    public async Task StaleOrUnsignedAccessTokenMustNotReachLiveProvider()
    {
        var store = new Store();
        var status = new LiveStatus();
        var service = new OrganizationProvisioningService(new SignedTokens(), status, store, Policy);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            service.CreateAsync("Client", "unsigned-operator.jwt", "admin.jwt", default));
        Assert.Empty(status.Checked);
        Assert.Empty(store.Saved);
    }

    private sealed class SignedTokens : IVerifiedOidcTokenSource
    {
        public Task<VerifiedOidcToken> VerifyAsync(string token, string audience, CancellationToken ct) =>
            token switch
            {
                "operator.jwt" when audience == Policy.OperatorAudience =>
                    Task.FromResult(new VerifiedOidcToken(Issuer, "operator-sub", ["platform_provisioner"])),
                "admin.jwt" when audience == Policy.AdminAudience =>
                    Task.FromResult(new VerifiedOidcToken(Issuer, "admin-sub", ["tenant_admin"])),
                _ => throw new UnauthorizedAccessException("Untrusted signature")
            };
    }

    private sealed class LiveStatus(string failure = "") : ILiveOidcTokenStatus
    {
        public List<string> Checked { get; } = [];
        public Task<LiveOidcTokenState> CheckAsync(string token, string audience, CancellationToken ct)
        {
            Checked.Add(token);
            var isOperator = token == "operator.jwt";
            if (failure == "status-outage") throw new InvalidOperationException("IdP unavailable");
            return Task.FromResult(new LiveOidcTokenState(
                failure != "inactive-operator" || !isOperator
                    ? failure != "inactive-admin" || isOperator : false,
                failure == "other-issuer" ? "https://evil.example.test" : Issuer,
                failure == "other-sub" ? "different-identity" : isOperator ? "operator-sub" : "admin-sub",
                [failure == "wrong-audience" ? "some-other-service" : audience],
                [failure == "missing-role" ? "role-removed" :
                    isOperator ? "platform_provisioner" : "tenant_admin"]));
        }
    }

    private sealed class Store : IOrganizationProvisioningStore
    {
        public List<VerifiedOrganizationEnrollment> Saved { get; } = [];
        public Task CreateAsync(VerifiedOrganizationEnrollment enrollment, CancellationToken ct)
        {
            Saved.Add(enrollment);
            return Task.CompletedTask;
        }
    }
}
