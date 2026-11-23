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
/// #183 / ADR 0141. Positive SQL-specific contract against disposable
/// PostgreSQL17, not a test of qualified issuance, WORM or completeness.
/// Physical INSERT order is deliberately opposite SQL ORDER BY issued_utc,id.
/// </summary>
public sealed class PostgresExportTimelineTests
{
    private static readonly byte[] OriginalDer = [0x30, 0x02, 0x01, 0x00];
    private static readonly UtcPeriod Period = new(
        new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));

    private static NpgsqlDataSource Database() =>
        NpgsqlDataSource.Create(
            Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("Disposable PostgreSQL17 test DB required."));

    private static async Task<Guid> NewTenantAsync(NpgsqlDataSource db)
    {
        var tenant = Guid.NewGuid();
        await using var connection = await db.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-pg-export-timeline')",
            connection);
        cmd.Parameters.AddWithValue("id", tenant);
        cmd.Parameters.AddWithValue("name", "CI ordered v1 export " + tenant.ToString("N"));
        Assert.Equal(tenant, Assert.IsType<Guid>(await cmd.ExecuteScalarAsync()));
        return tenant;
    }

    private static async Task SeedAsync(
        NpgsqlDataSource db, Guid tenant, Guid id, DateTime utc)
    {
        await using var connection = await db.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO public.timestamp_registry
                (id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
                 policy_oid, provider_id, token_sha256_hex, validation_state,
                 response_der, evidence_reference)
            VALUES (@id, @org, @utc, @algorithm, @imprint, @policy, @provider,
                    @sha, 0, @der, NULL::text)
            """, connection);
        cmd.Parameters.AddWithValue("id", id);
        cmd.Parameters.AddWithValue("org", tenant);
        cmd.Parameters.AddWithValue("utc", utc);
        cmd.Parameters.AddWithValue("algorithm", "2.16.840.1.101.3.4.2.1");
        cmd.Parameters.AddWithValue("imprint", Convert.ToBase64String(new byte[32]));
        cmd.Parameters.AddWithValue("policy", "1.2.3");
        cmd.Parameters.AddWithValue("provider", "CI_UNQUALIFIED_ORDERED_EXPORT");
        cmd.Parameters.AddWithValue("sha", Convert.ToHexString(SHA256.HashData(OriginalDer)));
        cmd.Parameters.AddWithValue("der", OriginalDer);
        Assert.Equal(1, await cmd.ExecuteNonQueryAsync());
    }

    [Fact]
    public async Task SqlPeriodExportAndPhysicalZipFollowTimestampUuidNotInsertionOrder()
    {
        await using var db = Database();
        var a = await NewTenantAsync(db);
        var b = await NewTenantAsync(db);
        var early = Guid.Parse("11111111-1111-4111-8111-111111111111");
        var tie = Guid.Parse("22222222-2222-4222-8222-222222222222");
        var later = Guid.Parse("33333333-3333-4333-8333-333333333333");
        var time = new DateTime(2026, 11, 15, 9, 0, 0, DateTimeKind.Utc);
        // PostgreSQL persists timestamp at microsecond precision; compare
        // exact equal-time UUID ties and a genuinely later whole second.
        await SeedAsync(db, a, later, time.AddSeconds(1));
        await SeedAsync(db, a, tie, time);
        await SeedAsync(db, a, early, time);
        await SeedAsync(db, b, Guid.NewGuid(), time);

        var service = new TimestampRegistryService(new PostgresTimestampRegistry(db));
        var bytes = await service.ExportZipAsync(a, Period, default);
        using var archive = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
        using var manifest = JsonDocument.Parse(archive.GetEntry("manifest.json")!.Open());
        var entries = manifest.RootElement.GetProperty("entries").EnumerateArray().ToArray();
        Assert.Equal(new[] { early, tie, later },
            entries.Select(row => row.GetProperty("Id").GetGuid()).ToArray());
        Assert.Equal(new[]
        {
            "manifest.json",
            $"tokens/{early:N}.tsr",
            $"tokens/{tie:N}.tsr",
            $"tokens/{later:N}.tsr"
        }, archive.Entries.Select(item => item.FullName).ToArray());

        foreach (var row in entries)
        {
            var id = row.GetProperty("Id").GetGuid();
            await using var stream = archive.GetEntry($"tokens/{id:N}.tsr")!.Open();
            using var buffer = new MemoryStream();
            await stream.CopyToAsync(buffer);
            Assert.Equal(OriginalDer, buffer.ToArray());
            Assert.Equal(Convert.ToHexString(SHA256.HashData(OriginalDer)),
                row.GetProperty("TokenSha256Hex").GetString());
        }

        var foreign = await service.ExportZipAsync(b, Period, default);
        using var foreignZip = new ZipArchive(new MemoryStream(foreign), ZipArchiveMode.Read);
        using var foreignManifest = JsonDocument.Parse(foreignZip.GetEntry("manifest.json")!.Open());
        Assert.Equal(1, foreignManifest.RootElement.GetProperty("count").GetInt32());
        Assert.DoesNotContain(archive.Entries.Select(x => x.FullName),
            name => name.StartsWith("tokens/", StringComparison.Ordinal) &&
                    name.Contains("nonexistent", StringComparison.Ordinal));
        var foreignIds = foreignManifest.RootElement.GetProperty("entries")
            .EnumerateArray().Select(e => e.GetProperty("Id").GetGuid()).ToArray();
        Assert.DoesNotContain(early, foreignIds);
        Assert.DoesNotContain(tie, foreignIds);
        Assert.DoesNotContain(later, foreignIds);
    }
}
