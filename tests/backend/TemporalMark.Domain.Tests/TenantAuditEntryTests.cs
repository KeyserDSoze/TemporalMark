using TemporalMark.Domain;
using TemporalMark.Domain.Audit;
using Xunit;

namespace TemporalMark.Domain.Tests;

public sealed class TenantAuditEntryTests
{
    private static readonly Guid Tenant = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly DateTimeOffset Now = new(2026, 11, 15, 9, 0, 0, TimeSpan.Zero);

    [Fact]
    public void RejectsReceiptAndPeriodMixedInSingleEvent()
    {
        var entry = new TenantAuditEntry(Guid.NewGuid(), Tenant, "user",
            TenantAuditAction.ReceiptDownloadPrepared, Now, Guid.NewGuid(), Now.AddDays(-1), Now);
        Assert.Throws<DomainRuleException>(entry.Validate);
    }

    [Fact]
    public void ImprintSearchAuditMustNotCarryReceiptOrPeriodMetadata()
    {
        var valid = new TenantAuditEntry(Guid.NewGuid(), Tenant, "user",
            TenantAuditAction.DocumentImprintSearchPerformed, Now, null, null, null);
        valid.Validate();

        Assert.Throws<DomainRuleException>(() =>
            (valid with { ReceiptId = Guid.NewGuid() }).Validate());
        Assert.Throws<DomainRuleException>(() =>
            (valid with { PeriodFromUtc = Now.AddDays(-1), PeriodToUtcExclusive = Now }).Validate());
    }

    [Fact]
    public void RejectsNonUtcTimestampAndSubjectWithControlCharacters()
    {
        var nonUtc = new TenantAuditEntry(Guid.NewGuid(), Tenant, "user",
            TenantAuditAction.ReceiptDownloadPrepared, Now.ToOffset(TimeSpan.FromHours(1)), Guid.NewGuid(), null, null);
        Assert.Throws<DomainRuleException>(nonUtc.Validate);

        var unsafeSubject = new TenantAuditEntry(Guid.NewGuid(), Tenant, "evil\nactor",
            TenantAuditAction.ReceiptDownloadPrepared, Now, Guid.NewGuid(), null, null);
        Assert.Throws<DomainRuleException>(unsafeSubject.Validate);
    }
}
