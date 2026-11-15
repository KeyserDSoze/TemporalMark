using TemporalMark.Domain.Stamping;

namespace TemporalMark.Business.Registry;

/// <summary>Every operation must be tenant-filtered; implementation must not expose cross-tenant reads.</summary>
public interface ITimestampRegistry
{
    Task<long> CountAsync(Guid organizationId, UtcPeriod period, CancellationToken cancellationToken);
    Task<IReadOnlyList<TimestampRecord>> PageAsync(
        Guid organizationId, UtcPeriod period, int offset, int limit, CancellationToken cancellationToken);
    Task<IReadOnlyList<TimestampRecord>> ForExportAsync(
        Guid organizationId, UtcPeriod period, int maxResults, CancellationToken cancellationToken);
}
