using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using TemporalMark.Business.Registry;
using TemporalMark.Domain;
using TemporalMark.Domain.Stamping;
using Xunit;

namespace TemporalMark.Business.Tests;

public sealed class TimestampRegistryServiceTests
{
    private static readonly Guid TenantA = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid TenantB = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly UtcPeriod Period = new(
        new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));

    [Fact]
    public async Task DownloadReceiptRejectsCrossTenantLeak()
    {
        var other = MakeRecord(TenantB);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new MaliciousRegistry(other)).DownloadReceiptAsync(
                TenantA, other.Id, default));
    }

    [Fact]
    public async Task DownloadReceiptForOwnerReturnsExactDer()
    {
        var own = MakeRecord(TenantA);
        var result = await new TimestampRegistryService(new FakeRegistry([own])).DownloadReceiptAsync(
            TenantA, own.Id, default);
        Assert.Equal(own.ResponseDer, result);
    }

    [Fact]
    public async Task PageRejectsRepositoryCrossTenantLeak()
    {
        var repository = new MaliciousRegistry(MakeRecord(TenantB));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(repository).PageAsync(TenantA, Period, 0, 50, default));
    }

    [Fact]
    public async Task PageForOwnerStillReturnsOneIntegrityCheckedRecord()
    {
        var record = MakeRecord(TenantA);
        var page = await new TimestampRegistryService(new FakeRegistry([record])).PageAsync(
            TenantA, Period, 0, 25, CancellationToken.None);
        Assert.Single(page);
        Assert.Equal(record, page[0]);
    }

    [Fact]
    public async Task PageRejectsCorruptedStoredReceiptDigest()
    {
        var record = MakeRecord(TenantA) with { TokenSha256Hex = "DEADBEEF" };
        await Assert.ThrowsAsync<DomainRuleException>(() =>
            new TimestampRegistryService(new FakeRegistry([record])).PageAsync(
                TenantA, Period, 0, 25, CancellationToken.None));
    }

    [Fact]
    public async Task PageRejectsTamperedDerEvenIfStoredDigestIsUnchanged()
    {
        var intact = MakeRecord(TenantA);
        var corrupt = intact with { ResponseDer = [0x30, 0x02, 0x01, 0x01] };
        await Assert.ThrowsAsync<DomainRuleException>(() =>
            new TimestampRegistryService(new FakeRegistry([corrupt])).PageAsync(
                TenantA, Period, 0, 25, CancellationToken.None));
    }

    [Fact]
    public async Task PageRejectsDuplicateIdsBeforeReturningAnyMetadata()
    {
        var sameId = MakeRecord(TenantA);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new FakeRegistry([sameId, sameId])).PageAsync(
                TenantA, Period, 0, 25, CancellationToken.None));
    }

    [Fact]
    public async Task ExportRejectsDuplicateReceiptIdsRatherThanProducingAmbiguousZipPaths()
    {
        var sameId = MakeRecord(TenantA);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new FakeRegistry([sameId, sameId]))
                .ExportZipAsync(TenantA, Period, CancellationToken.None));
    }

    [Fact]
    public async Task ExportContainsDerAndManifestForAuthorizedTenant()
    {
        var fake = new FakeRegistry(new[] { MakeRecord(TenantA), MakeRecord(TenantB) });
        var zipBytes = await new TimestampRegistryService(fake).ExportZipAsync(TenantA, Period, default);
        using var archive = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read);
        Assert.Equal(2, archive.Entries.Count);
        using var manifest = JsonDocument.Parse(archive.GetEntry("manifest.json")!.Open());
        Assert.Equal(1, manifest.RootElement.GetProperty("count").GetInt32());
        Assert.Equal(TenantA.ToString(), manifest.RootElement.GetProperty("organizationId").GetString());
    }

    [Fact]
    public async Task ExportRejectsCrossTenantRepositoryBug()
    {
        var malicious = new MaliciousRegistry(MakeRecord(TenantB));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(malicious).ExportZipAsync(TenantA, Period, default));
    }

    [Fact]
    public async Task ExportRejectsCorruptStoredToken()
    {
        var valid = MakeRecord(TenantA);
        var damaged = valid with { TokenSha256Hex = "ABCD" };
        await Assert.ThrowsAsync<DomainRuleException>(() =>
            new TimestampRegistryService(new MaliciousRegistry(damaged)).ExportZipAsync(TenantA, Period, default));
    }

    private static TimestampRecord MakeRecord(Guid tenant)
    {
        var der = new byte[] { 0x30, 0x02, 0x01, 0x00 };
        return new TimestampRecord(Guid.NewGuid(), tenant,
            new DateTimeOffset(2026, 11, 15, 9, 0, 0, TimeSpan.Zero),
            "2.16.840.1.101.3.4.2.1", Convert.ToBase64String(new byte[32]),
            "1.2.3", "test-provider", Convert.ToHexString(SHA256.HashData(der)),
            TimestampValidationState.Unverified, der, null);
    }

    private sealed class FakeRegistry(IReadOnlyList<TimestampRecord> data) : ITimestampRegistry
    {
        private IEnumerable<TimestampRecord> Filter(Guid org, UtcPeriod period) =>
            data.Where(x => x.OrganizationId == org && period.Contains(x.IssuedUtc));
        public Task<TimestampRecord?> FindByIdAsync(Guid org, Guid id, CancellationToken ct) =>
            Task.FromResult(data.FirstOrDefault(x => x.OrganizationId == org && x.Id == id));
        public Task<long> CountAsync(Guid org, UtcPeriod period, CancellationToken ct) =>
            Task.FromResult((long)Filter(org, period).Count());
        public Task<IReadOnlyList<TimestampRecord>> PageAsync(Guid org, UtcPeriod period, int offset, int limit, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<TimestampRecord>>(Filter(org, period).Skip(offset).Take(limit).ToArray());
        public Task<IReadOnlyList<TimestampRecord>> ForExportAsync(Guid org, UtcPeriod period, int max, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<TimestampRecord>>(Filter(org, period).Take(max).ToArray());
    }

    private sealed class MaliciousRegistry(TimestampRecord record) : ITimestampRegistry
    {
        public Task<TimestampRecord?> FindByIdAsync(Guid org, Guid id, CancellationToken ct) => Task.FromResult<TimestampRecord?>(record);
        public Task<long> CountAsync(Guid org, UtcPeriod period, CancellationToken ct) => Task.FromResult(1L);
        public Task<IReadOnlyList<TimestampRecord>> PageAsync(Guid org, UtcPeriod period, int off, int lim, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<TimestampRecord>>(new[] { record });
        public Task<IReadOnlyList<TimestampRecord>> ForExportAsync(Guid org, UtcPeriod period, int max, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<TimestampRecord>>(new[] { record });
    }
}
