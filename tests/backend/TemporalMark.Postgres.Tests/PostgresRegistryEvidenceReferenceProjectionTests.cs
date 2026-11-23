using System.Security.Cryptography;
using Npgsql;
using TemporalMark.Business.Registry;
using TemporalMark.Domain.Stamping;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// #175 / ADR 0133: disposable PG17 evidence_reference wire-projection tests.
/// Source text is synthesized inside PostgreSQL, never copied to test logs.
/// Provider itself must reject an over-budget read, not merely Business.
/// </summary>
public sealed class PostgresRegistryEvidenceReferenceProjectionTests
{
    private const int OneMiB = 1024 * 1024;
    private const int EightMiB = 8 * OneMiB;
    private static readonly DateTime Issued =
        new(2026, 11, 15, 9, 0, 0, DateTimeKind.Utc);
    private static readonly UtcPeriod Period = new(
        new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));
    private static readonly string Imprint = Convert.ToBase64String(new byte[32]);
    private static readonly string DerHash =
        Convert.ToHexString(SHA256.HashData(new byte[] { 0x30, 0x02, 0x01, 0x00 }));

    private static NpgsqlDataSource Database() =>
        NpgsqlDataSource.Create(
            Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("Disposable PostgreSQL test DB required."));

    private static async Task<Guid> NewTenantAsync(NpgsqlDataSource db)
    {
        var id = Guid.NewGuid();
        await using var connection = await db.OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-pg-reference-projection')",
            connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("name", "CI PG reference projection " + id.ToString("N"));
        Assert.Equal(id, Assert.IsType<Guid>(await command.ExecuteScalarAsync()));
        return id;
    }

    private static async Task<Guid> SeedAsync(
        NpgsqlDataSource db, Guid org, int characterCount, string fill = "R",
        int issuedSeconds = 0, bool hasReference = true)
    {
        await using var connection = await db.OpenConnectionAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO public.timestamp_registry
                (id, organization_id, issued_utc, hash_algorithm_oid,
                 digest_base64, policy_oid, provider_id, token_sha256_hex,
                 validation_state, response_der, evidence_reference)
            VALUES (gen_random_uuid(), @org, @issued + @seconds * interval '1 second',
                    '2.16.840.1.101.3.4.2.1', @imprint, '1.2.3',
                    'CI_ONLY_REFERENCE_PROJECTION', @sha, 0,
                    decode('30020100', 'hex'),
                    CASE WHEN @has_ref THEN repeat(@fill, @characters)
                         ELSE NULL::text END)
            RETURNING id
            """, connection);
        command.Parameters.AddWithValue("org", org);
        command.Parameters.AddWithValue("issued", Issued);
        command.Parameters.AddWithValue("seconds", issuedSeconds);
        command.Parameters.AddWithValue("imprint", Imprint);
        command.Parameters.AddWithValue("sha", DerHash);
        command.Parameters.AddWithValue("has_ref", hasReference);
        command.Parameters.AddWithValue("fill", fill);
        command.Parameters.AddWithValue("characters", characterCount);
        return Assert.IsType<Guid>(await command.ExecuteScalarAsync());
    }

    [Fact]
    public async Task ReceiptRepositoryRejectsOverEightMiBReferenceBeforeMaterialization()
    {
        await using var db = Database();
        var org = await NewTenantAsync(db);
        var id = await SeedAsync(db, org, EightMiB + 1);
        var repo = new PostgresTimestampRegistry(db);

        var denied = await Assert.ThrowsAsync<ReceiptTooLargeException>(
            () => repo.FindByIdAsync(org, id, default));
        Assert.Equal(new ReceiptTooLargeException().Message, denied.Message);
        Assert.DoesNotContain(id.ToString(), denied.Message);
        Assert.DoesNotContain(org.ToString(), denied.Message);

        // Unknown and foreign identities stay unobservable instead of 409.
        Assert.Null(await repo.FindByIdAsync(Guid.NewGuid(), id, default));
        Assert.Null(await repo.FindByIdAsync(org, Guid.NewGuid(), default));
    }

    [Fact]
    public async Task PageRepositoryRejectsOversizedMultibyteUtf8Reference()
    {
        await using var db = Database();
        var org = await NewTenantAsync(db);
        // UTF-8 'é' is 2 bytes: 4,194,305 characters exceed 8MiB by 2 bytes.
        await SeedAsync(db, org, EightMiB / 2 + 1, fill: "é");
        var repo = new PostgresTimestampRegistry(db);

        var denied = await Assert.ThrowsAsync<InvalidOperationException>(
            () => repo.PageAsync(org, Period, 0, 10, default));
        Assert.Equal(
            "Registry evidence exceeded PostgreSQL pre-materialization byte limits.",
            denied.Message);
    }

    [Fact]
    public async Task ImprintSearchRepositoryRejectsOversizedReferenceBeforeResult()
    {
        await using var db = Database();
        var org = await NewTenantAsync(db);
        await SeedAsync(db, org, EightMiB + 1);
        var repo = new PostgresTimestampRegistry(db);

        var denied = await Assert.ThrowsAsync<InvalidOperationException>(
            () => repo.SearchByDigestAsync(org, Period, Imprint, 0, 2, default));
        Assert.Equal(
            "Registry evidence exceeded PostgreSQL pre-materialization byte limits.",
            denied.Message);
    }

    [Fact]
    public async Task PeriodZipProviderRejectsOversizedReferenceWithExistingTyped413Contract()
    {
        await using var db = Database();
        var org = await NewTenantAsync(db);
        await SeedAsync(db, org, EightMiB + 1);
        var repo = new PostgresTimestampRegistry(db);

        var denied = await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            repo.ForExportAsync(org, Period, TimestampRegistryService.ExportLimit + 1, default));
        Assert.Equal(new ExportTooLargeException().Message, denied.Message);
        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            new TimestampRegistryService(repo).ExportZipAsync(org, Period, default));
    }

    [Fact]
    public async Task CumulativeReferenceLimitIncludesAllChosenRowsAndSearchLookahead()
    {
        await using var db = Database();
        var org = await NewTenantAsync(db);
        var first = await SeedAsync(db, org, 4 * OneMiB, issuedSeconds: 0);
        await SeedAsync(db, org, 4 * OneMiB + 1, issuedSeconds: 1);
        var repo = new PostgresTimestampRegistry(db);

        // Individually both fit; the combined batch must not return even
        // the earlier valid row's DER or reference.
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            repo.PageAsync(org, Period, 0, 2, default));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            repo.SearchByDigestAsync(org, Period, Imprint, 0, 2, default));
        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            repo.ForExportAsync(org, Period, 2, default));

        // A single selected row can still be read with original metadata.
        var one = Assert.Single(await repo.PageAsync(org, Period, 0, 1, default));
        Assert.Equal(first, one.Id);
        Assert.Equal(4 * OneMiB, one.EvidenceReference!.Length);
        one.Validate();
    }

    [Fact]
    public async Task SevenMiBReferenceAndNullRemainIntactWithOtherTenantIsolation()
    {
        await using var db = Database();
        var a = await NewTenantAsync(db);
        var b = await NewTenantAsync(db);
        var largeId = await SeedAsync(db, a, 7 * OneMiB);
        var nullId = await SeedAsync(db, b, 0, hasReference: false);
        var repo = new PostgresTimestampRegistry(db);
        var expectedReference = new string('R', 7 * OneMiB);

        var single = await repo.FindByIdAsync(a, largeId, default);
        Assert.NotNull(single);
        Assert.Equal(expectedReference, single.EvidenceReference);
        single.Validate();

        var page = Assert.Single(await repo.PageAsync(a, Period, 0, 2, default));
        Assert.Equal(expectedReference, page.EvidenceReference);
        var search = Assert.Single(await repo.SearchByDigestAsync(a, Period, Imprint, 0, 2, default));
        Assert.Equal(expectedReference, search.EvidenceReference);
        var export = Assert.Single(await repo.ForExportAsync(a, Period, 2, default));
        Assert.Equal(expectedReference, export.EvidenceReference);
        Assert.Equal(single.ResponseDer, export.ResponseDer);

        var nullReceipt = await repo.FindByIdAsync(b, nullId, default);
        Assert.NotNull(nullReceipt);
        Assert.Null(nullReceipt.EvidenceReference);
        Assert.Null(Assert.Single(await repo.PageAsync(b, Period, 0, 2, default)).EvidenceReference);
        Assert.Null(await repo.FindByIdAsync(a, nullId, default));
        Assert.Null(await repo.FindByIdAsync(b, largeId, default));
    }
}
