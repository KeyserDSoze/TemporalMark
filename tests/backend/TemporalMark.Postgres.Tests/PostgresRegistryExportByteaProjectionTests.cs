using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;
using TemporalMark.Business.Registry;
using TemporalMark.Domain.Stamping;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// #173 / ADR 0131: disposable real PG17 provider export pre-wire tests.
/// Distinct org per test; server generates synthetic DER; never production data.
/// An exception at the provider boundary (not merely Business) is required.
/// </summary>
public sealed class PostgresRegistryExportByteaProjectionTests
{
    private const int OneMiB = 1024 * 1024;
    private static readonly UtcPeriod Period = new(
        new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));
    private static readonly DateTime Issued =
        new(2026, 11, 15, 9, 0, 0, DateTimeKind.Utc);
    private static readonly string DigestBase64 = Convert.ToBase64String(new byte[32]);

    private static NpgsqlDataSource Database() =>
        NpgsqlDataSource.Create(
            Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("Disposable PostgreSQL integration DB required."));

    private static async Task<Guid> NewTenantAsync(NpgsqlDataSource db)
    {
        var id = Guid.NewGuid();
        await using var connection = await db.OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-verified-export-boundary')",
            connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("name", "CI PG export projection " + id.ToString("N"));
        Assert.Equal(id, Assert.IsType<Guid>(await command.ExecuteScalarAsync()));
        return id;
    }

    private static async Task SeedAsync(
        NpgsqlDataSource db, Guid org, int count, int bytes, int firstSecond = 0)
    {
        // Synthetic SHA256 over the intended bytes, not a corrupted-hash
        // fixture. PostgreSQL creates those zero bytea rows without copying
        // up to 65 MiB of test payloads over the client/server connection.
        var sha256 = Convert.ToHexString(SHA256.HashData(new byte[bytes]));
        await using var connection = await db.OpenConnectionAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO public.timestamp_registry
                (id, organization_id, issued_utc, hash_algorithm_oid,
                 digest_base64, policy_oid, provider_id, token_sha256_hex,
                 validation_state, response_der, evidence_reference)
            SELECT gen_random_uuid(), @org, @issued + seq.i * interval '1 second',
                   '2.16.840.1.101.3.4.2.1', @digest, '1.2.3',
                   'CI_ONLY_EXPORT_PROJECTION', @sha, 0,
                   decode(repeat('00', @bytes), 'hex'), 'CI_ONLY_EXPORT_PROJECTION'
              FROM generate_series(@first, @last) AS seq(i)
            """, connection);
        command.Parameters.AddWithValue("org", org);
        command.Parameters.AddWithValue("issued", Issued);
        command.Parameters.AddWithValue("digest", DigestBase64);
        command.Parameters.AddWithValue("sha", sha256);
        command.Parameters.AddWithValue("bytes", bytes);
        command.Parameters.AddWithValue("first", firstSecond);
        command.Parameters.AddWithValue("last", firstSecond + count - 1);
        Assert.Equal(count, await command.ExecuteNonQueryAsync());
    }

    [Fact]
    public async Task ExportProviderRejectsOneShaConsistentOverOneMiBBeforeReturningDer()
    {
        await using var db = Database();
        var org = await NewTenantAsync(db);
        await SeedAsync(db, org, 1, OneMiB + 1);
        var repo = new PostgresTimestampRegistry(db);

        // RED on old ForExportAsync: the repository itself returns this
        // oversized original bytea rather than rejecting before delivery.
        var denied = await Assert.ThrowsAsync<ExportTooLargeException>(
            () => repo.ForExportAsync(org, Period, TimestampRegistryService.ExportLimit + 1, default));
        Assert.Equal(new ExportTooLargeException().Message, denied.Message);
        Assert.DoesNotContain(org.ToString(), denied.Message);
        Assert.DoesNotContain("CI_ONLY_EXPORT_PROJECTION", denied.Message);

        // The separate Business/HTTP 413 path must NOT change exception type.
        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            new TimestampRegistryService(repo).ExportZipAsync(org, Period, default));
    }

    [Fact]
    public async Task ExportProviderRejectsWhole65MiBAggregateBeforeReturningAnyDer()
    {
        await using var db = Database();
        var org = await NewTenantAsync(db);
        await SeedAsync(db, org, 65, OneMiB);
        var repo = new PostgresTimestampRegistry(db);
        var denied = await Assert.ThrowsAsync<ExportTooLargeException>(
            () => repo.ForExportAsync(org, Period, TimestampRegistryService.ExportLimit + 1, default));
        Assert.Equal(new ExportTooLargeException().Message, denied.Message);
        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            new TimestampRegistryService(repo).ExportZipAsync(org, Period, default));
    }

    [Fact]
    public async Task ExportProviderRejectsTenThousandAndOneTinyRowsBeforeReturningAnyDer()
    {
        await using var db = Database();
        var org = await NewTenantAsync(db);
        // 10,001 tiny receipts, each with matching SHA256, well within the
        // byte budget: ONLY row-count guard causes provider-level refusal.
        await SeedAsync(db, org, TimestampRegistryService.ExportLimit + 1, 4);
        var repo = new PostgresTimestampRegistry(db);
        var denied = await Assert.ThrowsAsync<ExportTooLargeException>(
            () => repo.ForExportAsync(org, Period, TimestampRegistryService.ExportLimit + 1, default));
        Assert.Equal(new ExportTooLargeException().Message, denied.Message);
        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            new TimestampRegistryService(repo).ExportZipAsync(org, Period, default));
    }

    [Fact]
    public async Task ExportProviderAllowsExactly64MiBAndBusinessMakesUntamperedZip()
    {
        await using var db = Database();
        var org = await NewTenantAsync(db);
        await SeedAsync(db, org, 64, OneMiB);
        var repo = new PostgresTimestampRegistry(db);
        var receipts = await repo.ForExportAsync(
            org, Period, TimestampRegistryService.ExportLimit + 1, default);
        Assert.Equal(64, receipts.Count);
        Assert.Equal(64L * OneMiB, receipts.Sum(x => (long)x.ResponseDer.Length));
        Assert.All(receipts, x => Assert.Equal(org, x.OrganizationId));
        receipts[0].Validate();
        receipts[^1].Validate();

        var archiveBytes = await new TimestampRegistryService(repo).ExportZipAsync(
            org, Period, default);
        using var zip = new ZipArchive(new MemoryStream(archiveBytes), ZipArchiveMode.Read);
        using var manifest = JsonDocument.Parse(zip.GetEntry("manifest.json")!.Open());
        Assert.Equal("temporalmark-period-export-v1",
            manifest.RootElement.GetProperty("format").GetString());
        Assert.Equal(64, manifest.RootElement.GetProperty("count").GetInt32());
        var first = zip.GetEntry($"tokens/{receipts[0].Id:N}.tsr");
        Assert.NotNull(first);
        Assert.Equal(OneMiB, first.Length);
        await using var firstBytes = new MemoryStream();
        await using (var rawEntry = first.Open())
            await rawEntry.CopyToAsync(firstBytes);
        Assert.Equal(receipts[0].ResponseDer, firstBytes.ToArray());
    }

    [Fact]
    public async Task ExportProviderPreservesEmptyOneMiBAndOtherTenantIsolation()
    {
        await using var db = Database();
        var tenantA = await NewTenantAsync(db);
        var tenantB = await NewTenantAsync(db);
        await SeedAsync(db, tenantA, 1, OneMiB);
        await SeedAsync(db, tenantB, 1, 4);
        var repo = new PostgresTimestampRegistry(db);

        var a = await repo.ForExportAsync(tenantA, Period, 2, default);
        var receipt = Assert.Single(a);
        Assert.Equal(tenantA, receipt.OrganizationId);
        Assert.Equal(OneMiB, receipt.ResponseDer.Length);
        receipt.Validate();
        var b = await repo.ForExportAsync(tenantB, Period, 2, default);
        Assert.Equal(4, Assert.Single(b).ResponseDer.Length);
        Assert.Equal(tenantB, b[0].OrganizationId);
        Assert.Empty(await repo.ForExportAsync(Guid.NewGuid(), Period, 2, default));
        Assert.Empty(await repo.ForExportAsync(tenantA,
            new UtcPeriod(
                new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
                new DateTimeOffset(2025, 2, 1, 0, 0, 0, TimeSpan.Zero)), 2, default));
    }
}
