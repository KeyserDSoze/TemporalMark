using System.Security.Cryptography;
using Npgsql;
using TemporalMark.Business.Registry;
using TemporalMark.Domain.Stamping;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// #172 / ADR 0130. Real disposable PostgreSQL 17 SELECT result-projection
/// boundaries, not a memory profiler or a legal timestamp verifier.
/// Every test uses a distinct organization and never writes to demo A/B.
/// </summary>
public sealed class PostgresRegistryByteaProjectionTests
{
    private const int OneMiB = 1024 * 1024;
    private const string RejectionMessage =
        "Registry evidence exceeded PostgreSQL pre-materialization byte limits.";
    private static readonly UtcPeriod Period = new(
        new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));
    private static readonly string Imprint = Convert.ToBase64String(new byte[32]);
    private static readonly DateTime IssuedUtc =
        new(2026, 11, 15, 9, 0, 0, DateTimeKind.Utc);

    private static NpgsqlDataSource Database() =>
        NpgsqlDataSource.Create(
            Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("Disposable PostgreSQL test DB is required."));

    private static async Task<Guid> NewOrganizationAsync(NpgsqlDataSource db)
    {
        var organizationId = Guid.NewGuid();
        await using var connection = await db.OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-pg-registry-byte-budget')",
            connection);
        command.Parameters.AddWithValue("id", organizationId);
        command.Parameters.AddWithValue("name", "CI bounded registry " + organizationId.ToString("N"));
        Assert.Equal(organizationId,
            Assert.IsType<Guid>(await command.ExecuteScalarAsync()));
        return organizationId;
    }

    /// <summary>
    /// PostgreSQL generates disposable ZERO bytea inside the server rather
    /// than sending 65MiB from a test client. SHA256 is computed independently
    /// from the exact byte count, so each row is checksum-consistent.
    /// </summary>
    private static async Task InsertAsync(
        NpgsqlDataSource db, Guid tenant, int rows, int bytes, int startSecond = 0)
    {
        var digest = Convert.ToHexString(SHA256.HashData(new byte[bytes]));
        await using var connection = await db.OpenConnectionAsync();
        await using var insert = new NpgsqlCommand("""
            INSERT INTO public.timestamp_registry
              (id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
               policy_oid, provider_id, token_sha256_hex, validation_state,
               response_der, evidence_reference)
            SELECT gen_random_uuid(), @tenant,
                   @issued + (seq.n * interval '1 second'),
                   '2.16.840.1.101.3.4.2.1', @imprint, '1.2.3',
                   'CI_ONLY_BYTE_PROJECTION', @sha, 0,
                   decode(repeat('00', @bytes), 'hex'), 'CI_ONLY_BYTE_PROJECTION'
              FROM generate_series(@first, @last) AS seq(n)
            """, connection);
        insert.Parameters.AddWithValue("tenant", tenant);
        insert.Parameters.AddWithValue("issued", IssuedUtc);
        insert.Parameters.AddWithValue("imprint", Imprint);
        insert.Parameters.AddWithValue("sha", digest);
        insert.Parameters.AddWithValue("bytes", bytes);
        insert.Parameters.AddWithValue("first", startSecond);
        insert.Parameters.AddWithValue("last", startSecond + rows - 1);
        Assert.Equal(rows, await insert.ExecuteNonQueryAsync());
    }

    [Fact]
    public async Task PageDeniesSingleShaConsistentOverOneMiBBeforeMaterializingItsDer()
    {
        await using var db = Database();
        var tenant = await NewOrganizationAsync(db);
        await InsertAsync(db, tenant, 1, OneMiB + 1);
        var repo = new PostgresTimestampRegistry(db);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => repo.PageAsync(tenant, Period, 0, 1, default));
        Assert.Equal(RejectionMessage, error.Message);
        Assert.DoesNotContain(tenant.ToString(), error.Message);

        // Do not accidentally change the separate synchronous ZIP contract:
        // its Business prehash budget must still throw ExportTooLargeException.
        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            new TimestampRegistryService(repo).ExportZipAsync(tenant, Period, default));
    }

    [Fact]
    public async Task SearchDeniesWholeLookaheadWhenSecondRowExceedsOneMiB()
    {
        await using var db = Database();
        var tenant = await NewOrganizationAsync(db);
        await InsertAsync(db, tenant, 1, 4, startSecond: 0);
        await InsertAsync(db, tenant, 1, OneMiB + 1, startSecond: 1);

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new PostgresTimestampRegistry(db)
                .SearchByDigestAsync(tenant, Period, Imprint, 0, 2, default));
        Assert.Equal(RejectionMessage, error.Message);

        // Same SQL statement with a 1-row bounded page remains legitimate.
        var first = await new PostgresTimestampRegistry(db)
            .SearchByDigestAsync(tenant, Period, Imprint, 0, 1, default);
        Assert.Single(first);
        Assert.Equal(4, first[0].ResponseDer.Length);
        first[0].Validate();
    }

    [Fact]
    public async Task PageAcceptsExactly64MiBButDenies65MiBInSameTenant()
    {
        await using var db = Database();
        var tenant = await NewOrganizationAsync(db);
        await InsertAsync(db, tenant, 65, OneMiB);
        var repo = new PostgresTimestampRegistry(db);

        var valid = await repo.PageAsync(tenant, Period, 0, 64, default);
        Assert.Equal(64, valid.Count);
        Assert.Equal(64L * OneMiB, valid.Sum(x => (long)x.ResponseDer.Length));
        // Independently validate first and last retained DER content/hash.
        valid[0].Validate();
        valid[^1].Validate();

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => repo.PageAsync(tenant, Period, 0, 65, default));
        Assert.Equal(RejectionMessage, error.Message);
    }

    [Fact]
    public async Task ValidBoundaryAndForeignTenantRemainAvailable()
    {
        await using var db = Database();
        var tenantA = await NewOrganizationAsync(db);
        var tenantB = await NewOrganizationAsync(db);
        await InsertAsync(db, tenantA, 1, OneMiB);
        await InsertAsync(db, tenantB, 1, 4);
        var repo = new PostgresTimestampRegistry(db);

        var pageA = await repo.PageAsync(tenantA, Period, 0, 2, default);
        var own = Assert.Single(pageA);
        Assert.Equal(tenantA, own.OrganizationId);
        Assert.Equal(OneMiB, own.ResponseDer.Length);
        own.Validate();

        var searchA = await repo.SearchByDigestAsync(
            tenantA, Period, Imprint, 0, 2, default);
        Assert.Equal(own.Id, Assert.Single(searchA).Id);

        var pageB = await repo.PageAsync(tenantB, Period, 0, 2, default);
        Assert.Equal(tenantB, Assert.Single(pageB).OrganizationId);
        Assert.Equal(4, pageB[0].ResponseDer.Length);
        Assert.Empty(await repo.PageAsync(tenantA, Period, 1, 2, default));
    }
}
