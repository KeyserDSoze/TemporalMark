using TemporalMark.Domain.Stamping;

namespace TemporalMark.Domain.Audit;

/// <summary>Preparation of evidence download, not proof of delivery or legal sealing.</summary>
public enum TenantAuditAction
{
    PeriodExportPrepared = 1,
    ReceiptDownloadPrepared = 2
}

/// <summary>No source documents, timestamps or token bytes in the audit metadata.</summary>
public sealed record TenantAuditEntry(
    Guid Id,
    Guid OrganizationId,
    string ActorSubjectId,
    TenantAuditAction Action,
    DateTimeOffset OccurredUtc,
    Guid? ReceiptId,
    DateTimeOffset? PeriodFromUtc,
    DateTimeOffset? PeriodToUtcExclusive)
{
    public void Validate()
    {
        if (Id == Guid.Empty || OrganizationId == Guid.Empty)
            throw new DomainRuleException("Audit event and organization IDs are required.");
        if (string.IsNullOrWhiteSpace(ActorSubjectId) || ActorSubjectId.Length > 255 ||
            ActorSubjectId != ActorSubjectId.Trim() ||
            ActorSubjectId.Any(char.IsControl))
            throw new DomainRuleException("A bounded, safe OIDC actor subject is required.");
        if (OccurredUtc.Offset != TimeSpan.Zero)
            throw new DomainRuleException("Audit time must be in UTC.");

        switch (Action)
        {
            case TenantAuditAction.PeriodExportPrepared:
                if (ReceiptId is not null || PeriodFromUtc is null || PeriodToUtcExclusive is null)
                    throw new DomainRuleException("Period export requires only a UTC interval.");
                try { _ = new UtcPeriod(PeriodFromUtc.Value, PeriodToUtcExclusive.Value); }
                catch (ArgumentException) { throw new DomainRuleException("Invalid UTC export interval."); }
                break;
            case TenantAuditAction.ReceiptDownloadPrepared:
                if (ReceiptId is null || ReceiptId == Guid.Empty ||
                    PeriodFromUtc is not null || PeriodToUtcExclusive is not null)
                    throw new DomainRuleException("Receipt download requires only a receipt ID.");
                break;
            default:
                throw new DomainRuleException("Unrecognized audit action.");
        }
    }
}
