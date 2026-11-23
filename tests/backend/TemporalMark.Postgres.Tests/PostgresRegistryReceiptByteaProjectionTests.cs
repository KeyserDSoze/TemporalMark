using System.Security.Cryptography;
using Npgsql;
using TemporalMark.Business.Registry;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// #174 / ADR 0132: real disposable PG17 receipt read-boundary tests.
/// Require provider denial before Npgsql materializes an oversized bytea;
/// Business's preexisting 1 MiB policy alone is NOT sufficient.
/// </summary>
public sealed class PostgresRegistryReceiptByteaProjectionTests
{
    private const int OneMiB = 1024 * 1024;
    private static readonly DateTime Issued =
        new(2026, 11, 15, 9, 0, 0, DateTimeKind.Utc);
    private static readonly string Imprint = Convert.ToBase64String(new byte[32]);

    private static NpgsqlDataSource Database() =>
        NpgsqlDataSource.Create(
            Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("Disposable PostgreSQL test DB required."));

    private static async Task<Guid> NewTenantAsync(NpgsqlDataSource db)
    {
        var id = Guid.NewGuid();
        await using var connection = await db.OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-pg-receipt-projection')",
            connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("name", "CI PG single-receipt projection " + id.ToString("N"));
        Assert.Equal(id, Assert.IsType<Guid>(await command.ExecuteScalarAsync()));
        return id;
    }

    private static async Task<(Guid Id, string Sha256)> SeedAsync(
        NpgsqlDataSource db, Guid org, int byteCount)
    {
        // Synthetic server-side zero bytea; SHA256 is independently computed
        // over the same number of bytes. Never log the evidence, digest or ID.
        var sha = Convert.ToHexString(SHA256.HashData(new byte[byteCount]));
        await using var connection = await db.OpenConnectionAsync();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO public.timestamp_registry
                (id, organization_id, issued_utc, hash_algorithm_oid,
                 digest_base64, policy_oid, provider_id, token_sha256_hex,
                 validation_state, response_der, evidence_reference)
            VALUES (gen_random_uuid(), @org, @issued,
                    '2.16.840.1.101.3.4.2.1', @digest, '1.2.3',
                    'CI_ONLY_RECEIPT_PROJECTION', @sha, 0,
                    decode(repeat('00', @bytes), 'hex'), 'CI_ONLY_RECEIPT_PROJECTION')
            RETURNING id
            """, connection);
        insert.Parameters.AddWithValue("org", org);
        insert.Parameters.AddWithValue("issued", Issued);
        insert.Parameters.AddWithValue("digest", Imprint);
        insert.Parameters.AddWithValue("sha", sha);
        insert.Parameters.AddWithValue("bytes", byteCount);
        return (Assert.IsType<Guid>(await insert.ExecuteScalarAsync()), sha);
    }

    [Fact]
    public async Task FindByIdRejectsOverOneMiBShaConsistentReceiptAtProviderBoundary()
    {
        await using var db = Database();
        var org = await NewTenantAsync(db);
        var (id, sha) = await SeedAsync(db, org, OneMiB + 1);
        var repo = new PostgresTimestampRegistry(db);

        // Test-only RED on old SQL: FindByIdAsync returned the oversized
        // byte[]; only DownloadReceiptAsync rejected it *after* transfer.
        var denied = await Assert.ThrowsAsync<ReceiptTooLargeException>(
            () => repo.FindByIdAsync(org, id, default));
        Assert.Equal(new ReceiptTooLargeException().Message, denied.Message);
        Assert.DoesNotContain(org.ToString(), denied.Message);
        Assert.DoesNotContain(id.ToString(), denied.Message);
        Assert.DoesNotContain(sha, denied.Message);
        Assert.DoesNotContain("CI_ONLY_RECEIPT_PROJECTION", denied.Message);

        await Assert.ThrowsAsync<ReceiptTooLargeException>(
            () => new TimestampRegistryService(repo).DownloadReceiptAsync(org, id, default));
    }

    [Fact]
    public async Task FindByIdPreservesExactOneMiBAndFourByteReceiptsAndRequestedIdentity()
    {
        await using var db = Database();
        var org = await NewTenantAsync(db);
        var (boundaryId, _) = await SeedAsync(db, org, OneMiB);
        var (smallId, _) = await SeedAsync(db, org, 4);
        var repo = new PostgresTimestampRegistry(db);

        var boundary = await repo.FindByIdAsync(org, boundaryId, default);
        Assert.NotNull(boundary);
        Assert.Equal(org, boundary.OrganizationId);
        Assert.Equal(boundaryId, boundary.Id);
        Assert.Equal(OneMiB, boundary.ResponseDer.Length);
        Assert.Equal(new byte[OneMiB], boundary.ResponseDer);
        boundary.Validate();

        var small = await repo.FindByIdAsync(org, smallId, default);
        Assert.NotNull(small);
        Assert.Equal(smallId, small.Id);
        Assert.Equal(new byte[4], small.ResponseDer);
        small.Validate();

        var business = new TimestampRegistryService(repo);
        Assert.Equal(boundary.ResponseDer,
            await business.DownloadReceiptAsync(org, boundaryId, default));
        Assert.Equal(small.ResponseDer,
            await business.DownloadReceiptAsync(org, smallId, default));
        Assert.Null(await repo.FindByIdAsync(org, Guid.NewGuid(), default));
    }

    [Fact]
    public async Task OversizedForeignTenantIsNotDisclosedAndMissingIsNotConflict()
    {
        await using var db = Database();
        var a = await NewTenantAsync(db);
        var b = await NewTenantAsync(db);
        var (bigB, _) = await SeedAsync(db, b, OneMiB + 1);
        var (smallA, _) = await SeedAsync(db, a, 4);
        var repo = new PostgresTimestampRegistry(db);

        // The WHERE tenant+exact ID predicate executes *before* any size
        // category can be observed. A receives null (HTTP 404), not 409.
        Assert.Null(await repo.FindByIdAsync(a, bigB, default));
        Assert.Null(await new TimestampRegistryService(repo)
            .DownloadReceiptAsync(a, bigB, default));
        Assert.Null(await repo.FindByIdAsync(a, Guid.NewGuid(), default));
        Assert.Null(await repo.FindByIdAsync(b, smallA, default));
        Assert.Equal(smallA, (await repo.FindByIdAsync(a, smallA, default))!.Id);

        // The owning tenant alone observes the generic 409-mapped subtype.
        var denied = await Assert.ThrowsAsync<ReceiptTooLargeException>(
            () => repo.FindByIdAsync(b, bigB, default));
        Assert.Equal(new ReceiptTooLargeException().Message, denied.Message);
    }
}
