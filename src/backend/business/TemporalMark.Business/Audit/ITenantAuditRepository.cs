using TemporalMark.Domain.Audit;
using TemporalMark.Domain.Stamping;

namespace TemporalMark.Business.Audit;

/// <summary>Every operation MUST scope by server-resolved organization ID.</summary>
public interface ITenantAuditRepository
{
    Task AppendAsync(TenantAuditEntry entry, CancellationToken cancellationToken);
    Task<IReadOnlyList<TenantAuditEntry>> PageAsync(
        Guid organizationId, UtcPeriod period, int offset, int limit, CancellationToken cancellationToken);
}
