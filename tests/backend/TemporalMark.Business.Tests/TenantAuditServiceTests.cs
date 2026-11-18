using TemporalMark.Business.Audit;
using TemporalMark.Domain.Audit;
using TemporalMark.Domain.Stamping;
using Xunit;

namespace TemporalMark.Business.Tests;

public sealed class TenantAuditServiceTests
{
    private static readonly Guid Tenant = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid OtherTenant = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly UtcPeriod November = new(
        new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));

    [Fact]
    public async Task PreparingPeriodExportPersistsBoundedActorAndUtcPeriod()
    {
        var repository = new FakeAuditRepository();
        await new TenantAuditService(repository).PreparePeriodExportAsync(Tenant, "oidc-subject", November, default);
        var saved = Assert.Single(repository.Written);
        Assert.Equal(Tenant, saved.OrganizationId);
        Assert.Equal("oidc-subject", saved.ActorSubjectId);
        Assert.Equal(TenantAuditAction.PeriodExportPrepared, saved.Action);
        Assert.Equal(November.FromUtc, saved.PeriodFromUtc);
        Assert.Equal(November.ToUtcExclusive, saved.PeriodToUtcExclusive);
        Assert.Null(saved.ReceiptId);
        Assert.Equal(TimeSpan.Zero, saved.OccurredUtc.Offset);
    }

    [Fact]
    public async Task PreparingReceiptDownloadRecordsOnlyReceiptId()
    {
        var repository = new FakeAuditRepository();
        var receipt = Guid.NewGuid();
        await new TenantAuditService(repository).PrepareReceiptDownloadAsync(Tenant, "oidc-subject", receipt, default);
        var saved = Assert.Single(repository.Written);
        Assert.Equal(TenantAuditAction.ReceiptDownloadPrepared, saved.Action);
        Assert.Equal(receipt, saved.ReceiptId);
        Assert.Null(saved.PeriodFromUtc);
        Assert.Null(saved.PeriodToUtcExclusive);
    }

    [Fact]
    public async Task ImprintSearchAuditRecordsOnlyAuthenticatedScopeNeverQueryOrMatchMetadata()
    {
        var repository = new FakeAuditRepository();
        await new TenantAuditService(repository).PrepareImprintSearchAsync(
            Tenant, "signed-oidc-sub", default);

        var entry = Assert.Single(repository.Written);
        Assert.Equal(Tenant, entry.OrganizationId);
        Assert.Equal("signed-oidc-sub", entry.ActorSubjectId);
        Assert.Equal(TenantAuditAction.DocumentImprintSearchPerformed, entry.Action);
        Assert.Null(entry.ReceiptId);
        Assert.Null(entry.PeriodFromUtc);
        Assert.Null(entry.PeriodToUtcExclusive);
        Assert.Equal(TimeSpan.Zero, entry.OccurredUtc.Offset);
    }

    [Fact]
    public async Task ImprintSearchAuditRejectsInvalidScopeBeforeAppendAndFailsClosedOnWriteOutage()
    {
        var repository = new FakeAuditRepository();
        var service = new TenantAuditService(repository);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.PrepareImprintSearchAsync(Guid.Empty, "signed-oidc-sub", default));
        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.PrepareImprintSearchAsync(Tenant, "bad\nactor", default));
        Assert.Empty(repository.Written);

        repository.RejectWrites = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.PrepareImprintSearchAsync(Tenant, "signed-oidc-sub", default));
        Assert.Empty(repository.Written);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public async Task EmptyActorIsRejectedBeforeDatabaseWrite(string actor)
    {
        var repository = new FakeAuditRepository();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new TenantAuditService(repository).PreparePeriodExportAsync(Tenant, actor, November, default));
        Assert.Empty(repository.Written);
    }

    [Fact]
    public async Task EmptyReceiptIdIsRejectedBeforeDatabaseWrite()
    {
        var repository = new FakeAuditRepository();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new TenantAuditService(repository).PrepareReceiptDownloadAsync(Tenant, "subject", Guid.Empty, default));
        Assert.Empty(repository.Written);
    }

    [Fact]
    public async Task PageRejectsLeakedOtherTenantOrTimeRange()
    {
        var bad = new FakeAuditRepository { Returned = [Entry(OtherTenant)] };
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TenantAuditService(bad).PageAsync(Tenant, November, 0, 50, default));

        bad.Returned = [Entry(Tenant) with { OccurredUtc = November.ToUtcExclusive }];
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TenantAuditService(bad).PageAsync(Tenant, November, 0, 50, default));
    }

    [Fact]
    public async Task PageLimitIsBounded()
    {
        var repository = new FakeAuditRepository();
        var service = new TenantAuditService(repository);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            service.PageAsync(Tenant, November, -1, 50, default));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            service.PageAsync(Tenant, November, 0, 201, default));
    }

    [Fact]
    public async Task DatabaseWriteFailureFailsClosed()
    {
        var repository = new FakeAuditRepository { RejectWrites = true };
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TenantAuditService(repository).PreparePeriodExportAsync(Tenant, "subject", November, default));
    }

    private static TenantAuditEntry Entry(Guid tenant) =>
        new(Guid.NewGuid(), tenant, "subject", TenantAuditAction.PeriodExportPrepared,
            new DateTimeOffset(2026, 11, 15, 9, 0, 0, TimeSpan.Zero),
            null, November.FromUtc, November.ToUtcExclusive);

    private sealed class FakeAuditRepository : ITenantAuditRepository
    {
        public List<TenantAuditEntry> Written { get; } = [];
        public IReadOnlyList<TenantAuditEntry> Returned { get; set; } = [];
        public bool RejectWrites { get; set; }

        public Task AppendAsync(TenantAuditEntry entry, CancellationToken ct)
        {
            if (RejectWrites) throw new InvalidOperationException("Database unavailable");
            Written.Add(entry);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<TenantAuditEntry>> PageAsync(
            Guid organizationId, UtcPeriod period, int offset, int limit, CancellationToken ct) =>
            Task.FromResult(Returned);
    }
}
