using System.Security.Cryptography;
using Npgsql;
using TemporalMark.Business.Registry;
using TemporalMark.Domain.Stamping;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// #180 / ADR 0138. Real disposable PG17 owner-seeded *historical* rows:
/// NOT via the application writer (which now correctly denies new bad data).
/// No migration, production SQL credential or immutable evidence is changed.
/// </summary>
public sealed class PostgresLegacyCanonicalImprintReadTests
{
    private static readonly UtcPeriod Period = new(
        new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));
    private static readonly byte[] OriginalDer = [0x30, 0x02, 0x01, 0x00];
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    private static NpgsqlDataSource Database() =>
        NpgsqlDataSource.Create(
            Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("Disposable PostgreSQL test DB required."));

    private static async Task<Guid> NewTenantAsync(NpgsqlDataSource db)
    {
        var tenant = Guid.NewGuid();
        await using var connection = await db.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-legacy-imprint-read')",
            connection);
        cmd.Parameters.AddWithValue("id", tenant);
        cmd.Parameters.AddWithValue("name", "CI legacy imprint read " + tenant.ToString("N"));
        Assert.Equal(tenant, Assert.IsType<Guid>(await cmd.ExecuteScalarAsync()));
        return tenant;
    }

    private static async Task<Guid> SeedHistoricalAsync(
        NpgsqlDataSource db, Guid tenant, string algorithmOid, string digestBase64)
    {
        // Deliberately owner-only direct INSERT. The current app writer
        // correctly rejects malformed *new* imprints; this models old
        // row/restore corruption within V001's intentionally broad schema.
        await using var conn = await db.OpenConnectionAsync();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO public.timestamp_registry
                (id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
                 policy_oid, provider_id, token_sha256_hex, validation_state,
                 response_der, evidence_reference)
            VALUES (@id, @org, @issued, @oid, @digest,
                    '1.2.3', 'CI_LEGACY_ORIGINAL', @sha, 0, @der, NULL::text)
            """, conn);
        var id = Guid.NewGuid();
        insert.Parameters.AddWithValue("id", id);
        insert.Parameters.AddWithValue("org", tenant);
        insert.Parameters.AddWithValue("issued", new DateTime(2026, 11, 15, 9, 0, 0, DateTimeKind.Utc));
        insert.Parameters.AddWithValue("oid", algorithmOid);
        insert.Parameters.AddWithValue("digest", digestBase64);
        insert.Parameters.AddWithValue("sha", Convert.ToHexString(SHA256.HashData(OriginalDer)));
        insert.Parameters.AddWithValue("der", OriginalDer);
        Assert.Equal(1, await insert.ExecuteNonQueryAsync());
        return id;
    }

    private static (string Oid, string Imprint) Variant(string mutation)
    {
        var canonical = Convert.ToBase64String(new byte[32]);
        return mutation switch
        {
            "wrong-oid" => ("1.3.14.3.2.26", canonical),
            "pad-bit-alias" => (Sha256Oid, canonical[..42] + "B="),
            "decoded-31" => (Sha256Oid, Convert.ToBase64String(new byte[31])),
            "leading-whitespace" => (Sha256Oid, " " + canonical),
            _ => throw new InvalidOperationException("Unrecognized fixture.")
        };
    }

    [Theory]
    [InlineData("wrong-oid", "page")]
    [InlineData("wrong-oid", "receipt")]
    [InlineData("wrong-oid", "export")]
    [InlineData("pad-bit-alias", "page")]
    [InlineData("pad-bit-alias", "receipt")]
    [InlineData("pad-bit-alias", "export")]
    [InlineData("decoded-31", "page")]
    [InlineData("decoded-31", "receipt")]
    [InlineData("decoded-31", "export")]
    [InlineData("leading-whitespace", "page")]
    [InlineData("leading-whitespace", "receipt")]
    [InlineData("leading-whitespace", "export")]
    public async Task AuthorizedHistoricalNoncanonicalImprintIsNotDelivered(
        string mutation, string boundary)
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        var foreign = await NewTenantAsync(db);
        var (oid, imprint) = Variant(mutation);
        var id = await SeedHistoricalAsync(db, tenant, oid, imprint);

        var repository = new PostgresTimestampRegistry(db);
        var historical = await repository.FindByIdAsync(tenant, id, default);
        Assert.NotNull(historical);
        historical.Validate(); // Not a DER, status, tenant or UTC error.
        Assert.Equal(TimestampValidationState.Unverified, historical.ValidationState);
        Assert.Equal(imprint, historical.DigestBase64);
        Assert.Equal(oid, historical.HashAlgorithmOid);
        Assert.Equal(OriginalDer, historical.ResponseDer);
        Assert.Null(await repository.FindByIdAsync(foreign, id, default));

        var service = new TimestampRegistryService(repository);
        Func<Task> read = boundary switch
        {
            "page" => async () =>
            {
                _ = await service.PageAsync(tenant, Period, 0, 10, default);
            },
            "receipt" => async () =>
            {
                _ = await service.DownloadReceiptAsync(tenant, id, default);
            },
            "export" => async () =>
            {
                _ = await service.ExportZipAsync(tenant, Period, default);
            },
            _ => throw new InvalidOperationException("Unrecognized read boundary.")
        };
        var denied = await Assert.ThrowsAsync<InvalidOperationException>(read);
        Assert.Equal("Repository returned an unsupported pilot document imprint.", denied.Message);
        Assert.DoesNotContain(tenant.ToString(), denied.Message);
        Assert.DoesNotContain(id.ToString(), denied.Message);
        Assert.DoesNotContain(imprint, denied.Message);
        Assert.DoesNotContain(oid, denied.Message);

        // Read denial must neither rewrite the owner's source metadata nor
        // turn a foreign authorized lookup into an existence oracle.
        var after = await repository.FindByIdAsync(tenant, id, default);
        Assert.NotNull(after);
        Assert.Equal(oid, after.HashAlgorithmOid);
        Assert.Equal(imprint, after.DigestBase64);
        Assert.Equal(historical.TokenSha256Hex, after.TokenSha256Hex);
        Assert.Equal(OriginalDer, after.ResponseDer);
        Assert.Null(await service.DownloadReceiptAsync(foreign, id, default));
        Assert.Empty(await service.PageAsync(foreign, Period, 0, 10, default));
    }

    [Fact]
    public async Task HistoricalCanonicalNonzeroImprintStillSearchesAndDownloadsOnlyForOwner()
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        var foreign = await NewTenantAsync(db);
        var original = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var imprint = Convert.ToBase64String(original);
        var id = await SeedHistoricalAsync(db, tenant, Sha256Oid, imprint);
        var service = new TimestampRegistryService(new PostgresTimestampRegistry(db));

        Assert.Equal(id, Assert.Single(await service.PageAsync(tenant, Period, 0, 10, default)).Id);
        Assert.Equal(id, Assert.Single((await service.SearchByDocumentSha256Async(
            tenant, Period, Convert.ToHexString(original), 0, 10, default)).Items).Id);
        Assert.Equal(OriginalDer, await service.DownloadReceiptAsync(tenant, id, default));
        Assert.NotEmpty(await service.ExportZipAsync(tenant, Period, default));
        Assert.Null(await service.DownloadReceiptAsync(foreign, id, default));
        Assert.Empty((await service.SearchByDocumentSha256Async(
            foreign, Period, Convert.ToHexString(original), 0, 10, default)).Items);
    }
}
