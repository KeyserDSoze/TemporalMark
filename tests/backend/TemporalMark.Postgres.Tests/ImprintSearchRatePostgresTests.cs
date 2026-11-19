using Npgsql;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>RED-first live PostgreSQL 17, disposable tenant IDs; all replicas share one primary.</summary>
public sealed class ImprintSearchRatePostgresTests
{
    private static NpgsqlConnection OwnerConnection() =>
        new(Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("TEMPORALMARK_TEST_DB is required."));

    private static NpgsqlConnection RuntimeConnection()
    {
        var owner = new NpgsqlConnectionStringBuilder(Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("TEMPORALMARK_TEST_DB is required."))
        {
            Username = "temporalmark_api",
            Password = "local-dev-only"
        };
        return new NpgsqlConnection(owner.ConnectionString);
    }

    private static async Task<Guid> TenantAsync()
    {
        var org = Guid.NewGuid();
        await using var conn = OwnerConnection();
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@org, @name, 'verified-ci-admin')", conn);
        cmd.Parameters.AddWithValue("org", org);
        cmd.Parameters.AddWithValue("name", "Search quota CI " + org.ToString("N"));
        Assert.Equal(org, Assert.IsType<Guid>(await cmd.ExecuteScalarAsync()));
        return org;
    }

    private static async Task<(bool Allowed, int Retry)> Consume(Guid org, string actor)
    {
        await using var conn = RuntimeConnection();
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT allowed, retry_after_seconds FROM public.consume_imprint_search_rate(@org,@actor)", conn);
        cmd.Parameters.AddWithValue("org", org);
        cmd.Parameters.AddWithValue("actor", actor);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        var result = (reader.GetBoolean(0), reader.GetInt32(1));
        Assert.False(await reader.ReadAsync());
        return result;
    }

    [Fact]
    public async Task TwelvePerPrincipalThenGenericDenialWithoutIncrement()
    {
        var org = await TenantAsync();
        for (var i = 0; i < 12; i++)
            Assert.Equal((true, 0), await Consume(org, "verified-ci-admin"));

        var rejected = await Consume(org, "verified-ci-admin");
        Assert.False(rejected.Allowed);
        Assert.InRange(rejected.Retry, 1, 60);

        await using var conn = OwnerConnection();
        await conn.OpenAsync();
        await using var count = new NpgsqlCommand("""
            SELECT hits FROM public.imprint_search_rate_principals
            WHERE organization_id=@org AND actor_subject_id='verified-ci-admin'
            """, conn);
        count.Parameters.AddWithValue("org", org);
        Assert.Equal(12, Assert.IsType<int>(await count.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task TenantAggregateRestrictsRotatingPrincipalsButNotOtherTenants()
    {
        var a = await TenantAsync();
        var b = await TenantAsync();
        foreach (var actor in new[] { "principal-1", "principal-2", "principal-3" })
            for (var i = 0; i < 10; i++)
                Assert.Equal((true, 0), await Consume(a, actor));

        var denied = await Consume(a, "new-fourth-principal");
        Assert.False(denied.Allowed);
        Assert.InRange(denied.Retry, 1, 60);
        Assert.Equal((true, 0), await Consume(b, "principal-1"));
    }

    [Fact]
    public async Task SimultaneousSessionsNeverExceedSharedTenantBudget()
    {
        var org = await TenantAsync();
        // 72 distinct SQL sessions / 6 different authenticated principals.
        // Every successful result is serialized on PostgreSQL's tenant lock.
        var results = await Task.WhenAll(Enumerable.Range(0, 72).Select(i =>
            Consume(org, "parallel-principal-" + i % 6)));
        Assert.Equal(30, results.Count(x => x.Allowed));
        Assert.All(results.Where(x => !x.Allowed), x => Assert.InRange(x.Retry, 1, 60));

        await using var conn = OwnerConnection();
        await conn.OpenAsync();
        await using var total = new NpgsqlCommand("""
            SELECT sum(hits) FROM public.imprint_search_rate_principals WHERE organization_id=@org
            """, conn);
        total.Parameters.AddWithValue("org", org);
        Assert.Equal(30L, Assert.IsType<long>(await total.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task ExpiredWindowResetsButFutureClockSnapshotFailsClosed()
    {
        var org = await TenantAsync();
        Assert.Equal((true, 0), await Consume(org, "ci-actor"));
        await using var owner = OwnerConnection();
        await owner.OpenAsync();

        foreach (var table in new[] { "imprint_search_rate_tenants", "imprint_search_rate_principals" })
        {
            await using var expired = new NpgsqlCommand(
                $"UPDATE public.{table} SET window_start=now()-interval '5 minutes' WHERE organization_id=@org",
                owner);
            expired.Parameters.AddWithValue("org", org);
            await expired.ExecuteNonQueryAsync();
        }
        Assert.Equal((true, 0), await Consume(org, "ci-actor"));
        await using (var verify = new NpgsqlCommand("""
            SELECT hits FROM public.imprint_search_rate_principals
            WHERE organization_id=@org AND actor_subject_id='ci-actor'
            """, owner))
        {
            verify.Parameters.AddWithValue("org", org);
            Assert.Equal(1, Assert.IsType<int>(await verify.ExecuteScalarAsync()));
        }

        await using (var future = new NpgsqlCommand("""
            UPDATE public.imprint_search_rate_tenants
            SET window_start = now()+interval '5 minutes'
            WHERE organization_id=@org
            """, owner))
        {
            future.Parameters.AddWithValue("org", org);
            await future.ExecuteNonQueryAsync();
        }
        var error = await Assert.ThrowsAsync<PostgresException>(() => Consume(org, "ci-actor"));
        Assert.Equal(PostgresErrorCodes.InvalidParameterValue, error.SqlState);
    }

    [Fact]
    public async Task OnlyNarrowFunctionExecutableByRuntimeRoleWithoutTableAccess()
    {
        await using var conn = RuntimeConnection();
        await conn.OpenAsync();
        foreach (var table in new[] { "imprint_search_rate_tenants", "imprint_search_rate_principals" })
        {
            await using var read = new NpgsqlCommand($"SELECT count(*) FROM public.{table}", conn);
            var denied = await Assert.ThrowsAsync<PostgresException>(
                async () => await read.ExecuteScalarAsync());
            Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denied.SqlState);
        }
        await using var check = new NpgsqlCommand("""
            SELECT has_function_privilege(current_user,
                'public.consume_imprint_search_rate(uuid,text)', 'EXECUTE')
            """, conn);
        Assert.True(Assert.IsType<bool>(await check.ExecuteScalarAsync()));
    }
}
