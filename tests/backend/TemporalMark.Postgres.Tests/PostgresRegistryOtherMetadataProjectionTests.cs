using System.Security.Cryptography;
using Npgsql;
using TemporalMark.Business.Registry;
using TemporalMark.Domain.Stamping;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// #176 / ADR 0134: real disposable PostgreSQL17 SQL provider must gate
/// four V001 unbounded NOT NULL original metadata strings BEFORE GetString,
/// including every selected row, rather than rely on Business after wire.
/// </summary>
public sealed class PostgresRegistryOtherMetadataProjectionTests
{
    private const int FieldLimit = 16 * 1024;
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
        var org = Guid.NewGuid();
        await using var connection = await db.OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-pg-metadata-projection')",
            connection);
        command.Parameters.AddWithValue("id", org);
        command.Parameters.AddWithValue("name", "CI PG metadata projection " + org.ToString("N"));
        Assert.Equal(org, Assert.IsType<Guid>(await command.ExecuteScalarAsync()));
        return org;
    }

    private static async Task<Guid> SeedAsync(
        NpgsqlDataSource db, Guid org, string field = "", int characters = 0,
        string fill = "M", int seconds = 0)
    {
        // All identifiers and SQL columns are FIXED in the source query;
        // untrusted field selector is compared as an ordinary parameter.
        await using var connection = await db.OpenConnectionAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO public.timestamp_registry
                (id, organization_id, issued_utc, hash_algorithm_oid,
                 digest_base64, policy_oid, provider_id, token_sha256_hex,
                 validation_state, response_der, evidence_reference)
            VALUES (gen_random_uuid(), @org, @issued + @seconds * interval '1 second',
                    CASE WHEN @field = 'hash_algorithm_oid'
                         THEN repeat(@fill, @characters)
                         ELSE '2.16.840.1.101.3.4.2.1' END,
                    CASE WHEN @field = 'digest_base64'
                         THEN repeat(@fill, @characters)
                         ELSE @imprint END,
                    CASE WHEN @field = 'policy_oid'
                         THEN repeat(@fill, @characters)
                         ELSE '1.2.3' END,
                    CASE WHEN @field = 'provider_id'
                         THEN repeat(@fill, @characters)
                         ELSE 'CI_ONLY_METADATA_PROJECTION' END,
                    @sha, 0, decode('30020100','hex'), NULL::text)
            RETURNING id
            """, connection);
        command.Parameters.AddWithValue("org", org);
        command.Parameters.AddWithValue("issued", Issued);
        command.Parameters.AddWithValue("seconds", seconds);
        command.Parameters.AddWithValue("field", field);
        command.Parameters.AddWithValue("characters", characters);
        command.Parameters.AddWithValue("fill", fill);
        command.Parameters.AddWithValue("imprint", Imprint);
        command.Parameters.AddWithValue("sha", DerHash);
        return Assert.IsType<Guid>(await command.ExecuteScalarAsync());
    }

    [Theory]
    [InlineData("hash_algorithm_oid")]
    [InlineData("digest_base64")]
    [InlineData("policy_oid")]
    [InlineData("provider_id")]
    public async Task ReceiptProviderRejectsOver16KiBFieldBeforeTextWireProjection(
        string field)
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        var id = await SeedAsync(db, tenant, field, FieldLimit + 1);
        var repo = new PostgresTimestampRegistry(db);

        var denied = await Assert.ThrowsAsync<ReceiptTooLargeException>(
            () => repo.FindByIdAsync(tenant, id, default));
        Assert.Equal(new ReceiptTooLargeException().Message, denied.Message);
        Assert.DoesNotContain(id.ToString(), denied.Message);
        Assert.DoesNotContain(tenant.ToString(), denied.Message);
        Assert.Null(await repo.FindByIdAsync(Guid.NewGuid(), id, default));
        Assert.Null(await repo.FindByIdAsync(tenant, Guid.NewGuid(), default));
    }

    [Theory]
    [InlineData("hash_algorithm_oid")]
    [InlineData("digest_base64")]
    [InlineData("policy_oid")]
    [InlineData("provider_id")]
    public async Task PageProviderRejectsOver16KiBFieldBeforeAnyRecord(
        string field)
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        await SeedAsync(db, tenant, field, FieldLimit + 1);
        var denied = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new PostgresTimestampRegistry(db).PageAsync(tenant, Period, 0, 5, default));
        Assert.Equal(
            "Registry evidence exceeded PostgreSQL pre-materialization byte limits.",
            denied.Message);
    }

    [Theory]
    [InlineData("hash_algorithm_oid")]
    [InlineData("digest_base64")]
    [InlineData("policy_oid")]
    [InlineData("provider_id")]
    public async Task ExportProviderRejectsOver16KiBFieldWithTypedPeriodException(
        string field)
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        await SeedAsync(db, tenant, field, FieldLimit + 1);
        var repo = new PostgresTimestampRegistry(db);

        var denied = await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            repo.ForExportAsync(tenant, Period, 2, default));
        Assert.Equal(new ExportTooLargeException().Message, denied.Message);
    }

    [Fact]
    public async Task SearchLookaheadWithOverBudgetProviderDeniesWholeBatch()
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        var firstId = await SeedAsync(db, tenant, seconds: 0);
        await SeedAsync(db, tenant, field: "provider_id", characters: FieldLimit + 1, seconds: 1);
        var repo = new PostgresTimestampRegistry(db);

        // Valid first row alone is unchanged; matching second lookahead
        // must deny *both* before either original metadata is materialized.
        var one = Assert.Single(await repo.SearchByDigestAsync(
            tenant, Period, Imprint, 0, 1, default));
        Assert.Equal(firstId, one.Id);
        one.Validate();
        var denied = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            repo.SearchByDigestAsync(tenant, Period, Imprint, 0, 2, default));
        Assert.Equal(
            "Registry evidence exceeded PostgreSQL pre-materialization byte limits.",
            denied.Message);
    }

    [Fact]
    public async Task UnicodeProviderUsesUtf8ByteCountInsteadOfCharCount()
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        // 8,193 characters U+00E9 encode as 16,386 UTF8 bytes.
        var id = await SeedAsync(
            db, tenant, "provider_id", FieldLimit / 2 + 1, fill: "é");
        var denied = await Assert.ThrowsAsync<ReceiptTooLargeException>(() =>
            new PostgresTimestampRegistry(db).FindByIdAsync(tenant, id, default));
        Assert.Equal(new ReceiptTooLargeException().Message, denied.Message);
    }

    [Fact]
    public async Task IndividuallyInBudgetFourFieldsExceedCombinedTwoMiBBatch()
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        await using (var connection = await db.OpenConnectionAsync())
        await using (var command = new NpgsqlCommand("""
            INSERT INTO public.timestamp_registry
                (id, organization_id, issued_utc, hash_algorithm_oid,
                 digest_base64, policy_oid, provider_id, token_sha256_hex,
                 validation_state, response_der, evidence_reference)
            SELECT gen_random_uuid(), @org, @issued + g.n * interval '1 second',
                   repeat('H', @perfield), repeat('D', @perfield),
                   repeat('P', @perfield), repeat('Q', @perfield),
                   @sha, 0, decode('30020100','hex'), NULL::text
              FROM generate_series(0, 32) AS g(n)
            """, connection))
        {
            command.Parameters.AddWithValue("org", tenant);
            command.Parameters.AddWithValue("issued", Issued);
            command.Parameters.AddWithValue("perfield", FieldLimit);
            command.Parameters.AddWithValue("sha", DerHash);
            Assert.Equal(33, await command.ExecuteNonQueryAsync());
        }

        var repo = new PostgresTimestampRegistry(db);
        // Per field exactly at 16KiB inclusive: a single selected row
        // remains original and locally SHA-consistent/Unverified.
        var first = Assert.Single(await repo.PageAsync(tenant, Period, 0, 1, default));
        Assert.Equal(FieldLimit, first.ProviderId.Length);
        Assert.Equal(FieldLimit, first.PolicyOid.Length);
        Assert.Equal(FieldLimit, first.HashAlgorithmOid.Length);
        Assert.Equal(FieldLimit, first.DigestBase64.Length);
        first.Validate();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            repo.PageAsync(tenant, Period, 0, 33, default));
        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            repo.ForExportAsync(tenant, Period, 34, default));
    }

    [Fact]
    public async Task Exact16KiBAndNullEvidenceReferenceArePreservedAcrossReadRoutes()
    {
        await using var db = Database();
        var a = await NewTenantAsync(db);
        var b = await NewTenantAsync(db);
        var id = await SeedAsync(db, a, "provider_id", FieldLimit);
        var otherId = await SeedAsync(db, b);
        var repo = new PostgresTimestampRegistry(db);
        var expected = new string('M', FieldLimit);

        var receipt = await repo.FindByIdAsync(a, id, default);
        Assert.NotNull(receipt);
        Assert.Equal(expected, receipt.ProviderId);
        Assert.Null(receipt.EvidenceReference);
        receipt.Validate();
        Assert.Equal(expected, Assert.Single(await repo.PageAsync(
            a, Period, 0, 10, default)).ProviderId);
        Assert.Equal(expected, Assert.Single(await repo.SearchByDigestAsync(
            a, Period, Imprint, 0, 2, default)).ProviderId);
        Assert.Equal(expected, Assert.Single(await repo.ForExportAsync(
            a, Period, 2, default)).ProviderId);
        Assert.Null(await repo.FindByIdAsync(b, id, default));
        Assert.Null(await repo.FindByIdAsync(a, otherId, default));
    }

    [Fact]
    public async Task V001SchemaStillRefusesNullInEveryRequiredTextColumn()
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        await using var connection = await db.OpenConnectionAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO public.timestamp_registry
                (id, organization_id, issued_utc, hash_algorithm_oid,
                 digest_base64, policy_oid, provider_id, token_sha256_hex,
                 validation_state, response_der, evidence_reference)
            VALUES (gen_random_uuid(), @org, @issued,
                NULL::text, 'AA==', '1.2.3', 'p',
                @sha, 0, decode('30020100','hex'), NULL::text)
            """, connection);
        command.Parameters.AddWithValue("org", tenant);
        command.Parameters.AddWithValue("issued", Issued);
        command.Parameters.AddWithValue("sha", DerHash);
        var denied = await Assert.ThrowsAsync<PostgresException>(() =>
            command.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.NotNullViolation, denied.SqlState);
    }
}
