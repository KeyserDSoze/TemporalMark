using TemporalMark.Domain;
using TemporalMark.Domain.Tenancy;
using Xunit;

namespace TemporalMark.Domain.Tests;

public sealed class TenantMembershipPolicyTests
{
    private static readonly Guid Organization = Guid.Parse("11111111-1111-1111-1111-111111111111");

    [Fact]
    public void CannotRemoveLastActiveAdmin()
    {
        var members = new[] { new TenantMember(Organization, "alice", TenantRole.TenantAdmin, true) };
        Assert.Throws<DomainRuleException>(() =>
            TenantMembershipPolicy.EnsureCanRemoveOrDemote(Organization, "alice", members));
    }

    [Fact]
    public void CanRemoveAdminWhenAnotherActiveAdminRemains()
    {
        var members = new[] {
            new TenantMember(Organization, "alice", TenantRole.TenantAdmin, true),
            new TenantMember(Organization, "bob", TenantRole.TenantAdmin, true)
        };
        TenantMembershipPolicy.EnsureCanRemoveOrDemote(Organization, "alice", members);
    }

    [Fact]
    public void OtherOrganizationAdminDoesNotCount()
    {
        var members = new[] {
            new TenantMember(Organization, "alice", TenantRole.TenantAdmin, true),
            new TenantMember(Guid.NewGuid(), "bob", TenantRole.TenantAdmin, true)
        };
        Assert.Throws<DomainRuleException>(() =>
            TenantMembershipPolicy.EnsureCanRemoveOrDemote(Organization, "alice", members));
    }

    [Fact]
    public void InactiveAdminDoesNotCount()
    {
        var members = new[] {
            new TenantMember(Organization, "alice", TenantRole.TenantAdmin, true),
            new TenantMember(Organization, "bob", TenantRole.TenantAdmin, false)
        };
        Assert.Throws<DomainRuleException>(() =>
            TenantMembershipPolicy.EnsureCanRemoveOrDemote(Organization, "alice", members));
    }
}
