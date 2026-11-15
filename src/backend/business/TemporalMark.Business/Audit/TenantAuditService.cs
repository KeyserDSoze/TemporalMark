using TemporalMark.Domain.Audit;
using TemporalMark.Domain.Stamping;

namespace TemporalMark.Business.Audit;

/// <summary>
/// Append-only business audit. Prepared means authorized and ready for HTTP delivery,
/// never proof that a user received the file; this registry is not WORM/sealed.
/// </summary>
public sealed class TenantAuditService(ITenantAuditRepository repository)
{
    public Task PreparePeriodExportAsync(
        Guid organizationId, string actorSubjectId, UtcPeriod period, CancellationToken cancellationToken)
    {
        RequireInputs(organizationId, actorSubjectId);
        var entry = new TenantAuditEntry(Guid.NewGuid(), organizationId, actorSubjectId,
            TenantAuditAction.PeriodExportPrepared, DateTimeOffset.UtcNow,
            null, period.FromUtc, period.ToUtcExclusive);
        entry.Validate();
        return repository.AppendAsync(entry, cancellationToken);
    }

    public Task PrepareReceiptDownloadAsync(
        Guid organizationId, string actorSubjectId, Guid receiptId, CancellationToken cancellationToken)
    {
        RequireInputs(organizationId, actorSubjectId);
        if (receiptId == Guid.Empty)
            throw new ArgumentException("Receipt ID must not be empty.", nameof(receiptId));
        var entry = new TenantAuditEntry(Guid.NewGuid(), organizationId, actorSubjectId,
            TenantAuditAction.ReceiptDownloadPrepared, DateTimeOffset.UtcNow,
            receiptId, null, null);
        entry.Validate();
        return repository.AppendAsync(entry, cancellationToken);
    }

    public async Task<IReadOnlyList<TenantAuditEntry>> PageAsync(
        Guid organizationId, UtcPeriod period, int offset, int limit, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("Organization must be resolved from validated identity.", nameof(organizationId));
        if (offset < 0 || limit is < 1 or > 200)
            throw new ArgumentOutOfRangeException(nameof(limit), "Offset >= 0 and limit 1..200 required.");

        var entries = await repository.PageAsync(organizationId, period, offset, limit, cancellationToken);
        if (entries.Count > limit)
            throw new InvalidOperationException("Audit repository exceeded requested page size.");
        foreach (var entry in entries)
        {
            if (entry.OrganizationId != organizationId || !period.Contains(entry.OccurredUtc))
                throw new InvalidOperationException("Audit repository returned unauthorized organization or period.");
            entry.Validate();
        }
        return entries;
    }

    private static void RequireInputs(Guid organizationId, string actorSubjectId)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("Organization must be resolved from validated identity.", nameof(organizationId));
        if (string.IsNullOrWhiteSpace(actorSubjectId) || actorSubjectId.Length > 255 ||
            actorSubjectId != actorSubjectId.Trim() || actorSubjectId.Any(char.IsControl))
            throw new ArgumentException("A nonempty, bounded OIDC actor subject is required.", nameof(actorSubjectId));
    }
}
