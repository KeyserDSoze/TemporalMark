using TemporalMark.Domain.Stamping;

namespace TemporalMark.Business.Registry;

/// <summary>Only actual nonempty UTC days from a tenant-filtered database aggregate.</summary>
public sealed record RegistryDayCount(DateOnly DateUtc, long Count);

/// <summary>Every operation must be tenant-filtered; implementation must not expose cross-tenant reads.</summary>
public interface ITimestampRegistry
{
    Task<TimestampRecord?> FindByIdAsync(Guid organizationId, Guid recordId, CancellationToken cancellationToken);
    Task<long> CountAsync(Guid organizationId, UtcPeriod period, CancellationToken cancellationToken);
    Task<IReadOnlyList<RegistryDayCount>> CountByUtcDayAsync(
        Guid organizationId, UtcPeriod period, CancellationToken cancellationToken);
    Task<IReadOnlyList<TimestampRecord>> PageAsync(
        Guid organizationId, UtcPeriod period, int offset, int limit, CancellationToken cancellationToken);
    Task<IReadOnlyList<TimestampRecord>> ForExportAsync(
        Guid organizationId, UtcPeriod period, int maxResults, CancellationToken cancellationToken);
}
