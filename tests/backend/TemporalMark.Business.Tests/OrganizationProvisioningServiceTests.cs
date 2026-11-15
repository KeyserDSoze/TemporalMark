using System.Security.Cryptography;
using System.Text;
using TemporalMark.Business.Tenancy;
using Xunit;

namespace TemporalMark.Business.Tests;

public sealed class OrganizationProvisioningServiceTests
{
    private const string Issuer = "https://issuer.example.test/realm";
    private static readonly ProvisioningPolicy Policy = new(Issuer, "provisioning-api", "temporalmark-api");

    [Fact]
    public async Task TrustedOperatorAndFirstAdminAreDerivedFromSeparateTokens()
    {
        var store = new Store();
        var service = new OrganizationProvisioningService(new Tokens(), new LiveStatuses(), store, Policy);
        var id = await service.CreateAsync("Example Client", "valid-operator", "valid-admin", default);
        var entry = Assert.Single(store.Saved);
        Assert.Equal(id, entry.OrganizationId);
        Assert.NotEqual(Guid.Empty, id);
        Assert.Equal("initial-admin-sub", entry.FirstAdminSubject);
        Assert.Equal("operator-sub", entry.ProvisionerSubject);
        Assert.Equal(Issuer, entry.IdentityIssuer);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("valid-operator"))), entry.OperatorProofHashHex);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("valid-admin"))), entry.AdminProofHashHex);
        Assert.DoesNotContain("valid-admin", entry.ToString()!);
    }

    [Theory]
    [InlineData("operator-missing-role", "valid-admin")]
    [InlineData("valid-operator", "admin-missing-role")]
    [InlineData("operator-other-issuer", "valid-admin")]
    [InlineData("valid-operator", "admin-other-issuer")]
    [InlineData("operator-same-subject", "valid-admin")]
    [InlineData("valid-operator", "invalid-admin")]
    [InlineData("invalid-operator", "valid-admin")]
    [InlineData("valid-operator", "valid-operator")]
    public async Task UntrustedIdentityOrRoleNeverCreatesOrganization(string operatorProof, string adminProof)
    {
        var store = new Store();
        var service = new OrganizationProvisioningService(new Tokens(), new LiveStatuses(), store, Policy);
        await Assert.ThrowsAnyAsync<Exception>(() =>
            service.CreateAsync("Example Client", operatorProof, adminProof, default));
        Assert.Empty(store.Saved);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData(" Bad Name")]
    [InlineData("Bad\nName")]
    public async Task RejectsInvalidNameBeforeTokenVerification(string name)
    {
        var store = new Store();
        var verifier = new Tokens();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new OrganizationProvisioningService(verifier, new LiveStatuses(), store, Policy)
                .CreateAsync(name, "valid-operator", "valid-admin", default));
        Assert.Equal(0, verifier.Verifications);
        Assert.Empty(store.Saved);
    }

    [Fact]
    public async Task DatabaseWriteFailureStopsEnrollment()
    {
        var store = new Store { Reject = true };
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new OrganizationProvisioningService(new Tokens(), new LiveStatuses(), store, Policy)
                .CreateAsync("Example Client", "valid-operator", "valid-admin", default));
    }


    private sealed class LiveStatuses : ILiveOidcTokenStatus
    {
        public Task<LiveOidcTokenState> CheckAsync(string token, string audience, CancellationToken ct)
        {
            var operatorToken = audience == Policy.OperatorAudience;
            return Task.FromResult(new LiveOidcTokenState(true, Issuer,
                operatorToken ? "operator-sub" : "initial-admin-sub",
                [audience], [operatorToken ? "platform_provisioner" : "tenant_admin"]));
        }
    }

    private sealed class Tokens : IVerifiedOidcTokenSource
    {
        public int Verifications { get; private set; }
        public Task<VerifiedOidcToken> VerifyAsync(string token, string audience, CancellationToken ct)
        {
            Verifications++;
            if (token.StartsWith("invalid-", StringComparison.Ordinal))
                throw new UnauthorizedAccessException("JWT invalid");
            if (token == "valid-operator" && audience == Policy.OperatorAudience)
                return Task.FromResult(new VerifiedOidcToken(Issuer, "operator-sub", ["platform_provisioner"]));
            if (token == "valid-admin" && audience == Policy.AdminAudience)
                return Task.FromResult(new VerifiedOidcToken(Issuer, "initial-admin-sub", ["tenant_admin"]));
            if (token == "operator-missing-role" && audience == Policy.OperatorAudience)
                return Task.FromResult(new VerifiedOidcToken(Issuer, "operator-sub", []));
            if (token == "admin-missing-role" && audience == Policy.AdminAudience)
                return Task.FromResult(new VerifiedOidcToken(Issuer, "initial-admin-sub", []));
            if (token == "operator-other-issuer" && audience == Policy.OperatorAudience)
                return Task.FromResult(new VerifiedOidcToken("https://untrusted.example.test", "operator-sub", ["platform_provisioner"]));
            if (token == "admin-other-issuer" && audience == Policy.AdminAudience)
                return Task.FromResult(new VerifiedOidcToken("https://untrusted.example.test", "initial-admin-sub", ["tenant_admin"]));
            if (token == "operator-same-subject" && audience == Policy.OperatorAudience)
                return Task.FromResult(new VerifiedOidcToken(Issuer, "initial-admin-sub", ["platform_provisioner"]));
            throw new UnauthorizedAccessException("Invalid role or audience");
        }
    }

    private sealed class Store : IOrganizationProvisioningStore
    {
        public List<VerifiedOrganizationEnrollment> Saved { get; } = [];
        public bool Reject { get; set; }
        public Task CreateAsync(VerifiedOrganizationEnrollment entry, CancellationToken ct)
        {
            if (Reject) throw new InvalidOperationException("DB unavailable");
            Saved.Add(entry);
            return Task.CompletedTask;
        }
    }
}
