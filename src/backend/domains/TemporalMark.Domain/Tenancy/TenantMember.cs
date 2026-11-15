namespace TemporalMark.Domain.Tenancy;

public enum TenantRole
{
    TenantMember = 0,
    TenantAuditor = 1,
    TenantAdmin = 2
}

public sealed record TenantMember(
    Guid OrganizationId,
    string SubjectId,
    TenantRole Role,
    bool IsActive
);
