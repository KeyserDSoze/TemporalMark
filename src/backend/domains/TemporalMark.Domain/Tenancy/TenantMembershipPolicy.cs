using TemporalMark.Domain;

namespace TemporalMark.Domain.Tenancy;

/// <summary>Enforces the rule that an active organization always has an active admin.</summary>
public static class TenantMembershipPolicy
{
    public static void EnsureAtLeastOneActiveAdmin(
        Guid organizationId,
        IReadOnlyCollection<TenantMember> memberships)
    {
        ArgumentNullException.ThrowIfNull(memberships);
        if (organizationId == Guid.Empty)
            throw new DomainRuleException("Organization ID is required.");

        if (!memberships.Any(member =>
            member.OrganizationId == organizationId &&
            member.IsActive &&
            member.Role == TenantRole.TenantAdmin))
            throw new DomainRuleException("Each organization requires at least one active administrator.");
    }

    public static void EnsureCanRemoveOrDemote(
        Guid organizationId,
        string subjectId,
        IReadOnlyCollection<TenantMember> currentMemberships)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        var remaining = currentMemberships
            .Where(member => !(member.OrganizationId == organizationId && member.SubjectId == subjectId))
            .ToArray();
        EnsureAtLeastOneActiveAdmin(organizationId, remaining);
    }
}
