namespace TemporalMark.Business.Tenancy;

/// <summary>Checks membership in the authoritative organization database, not only JWT claims.</summary>
public interface ITenantAuthorization
{
    Task<bool> IsActiveAdminAsync(Guid organizationId, string subjectId, CancellationToken cancellationToken);
}
