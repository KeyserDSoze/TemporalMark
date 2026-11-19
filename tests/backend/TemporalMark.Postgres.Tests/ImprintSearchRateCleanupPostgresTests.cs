using Npgsql;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// RED-first: V020 must provide an owner-only bounded purge of idle quota
/// metadata, separate from original timestamp evidence/audit retention.
/// Operates exclusively on disposable PostgreSQL 17 CI tenant rows.
/// </summary>
public sealed class ImprintSearchRateCleanupPostgresTests
{
    private static NpgsqlConnection Owner() =>
        new(Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("TEMPORALMARK_TEST_DB is required."));

    private static NpgsqlConnection Runtime()
    {
        var builder = new NpgsqlConnectionStringBuilder(
            Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("TEMPORALMARK_TEST_DB is required."))
        {
            Username = "temporalmark_api",
            Password = "local-dev-only"
        };
        return new NpgsqlConnection(builder.ConnectionString);
    }

    private static async Task<Guid> CreateTenant()
    {
        var id = Guid.NewGuid();
        await using var conn = Owner();
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-cleanup-admin')", conn);
        cmd.Parameters.AddWithValue("id", id);
        cmd.Parameters.AddWithValue("name", "Quota cleanup CI " + id.ToString("N"));
        Assert.Equal(id, Assert.IsType<Guid>(await cmd.ExecuteScalarAsync()));
        return id;
    }

    private static async Task Consume(Guid organization, string actor)
    {
        await using var conn = Runtime();
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT allowed FROM public.consume_imprint_search_rate(@org,@actor)", conn);
        cmd.Parameters.AddWithValue("org", organization);
        cmd.Parameters.AddWithValue("actor", actor);
        Assert.True(Assert.IsType<bool>(await cmd.ExecuteScalarAsync()));
    }

    private static async Task<(int Principals, int Tenants)> Purge(int batch)
    {
        await using var conn = Owner();
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT * FROM public.purge_stale_imprint_search_rate_counters(@batch)", conn);
        cmd.Parameters.AddWithValue("batch", batch);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(2, reader.FieldCount); // Only counts; never tenant/actor identifiers.
        Assert.Equal("principal_deleted", reader.GetName(0));
        Assert.Equal("tenant_deleted", reader.GetName(1));
        var result = (reader.GetInt32(0), reader.GetInt32(1));
        Assert.InRange(result.Item1, 0, batch);
        Assert.InRange(result.Item2, 0, batch);
        Assert.False(await reader.ReadAsync());
        return result;
    }

    private static async Task<long> Count(Guid id, string table)
    {
        await using var conn = Owner();
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            $"SELECT count(*) FROM public.{table} WHERE {(table == "organizations" ? "id" : "organization_id")}=@org", conn);
        cmd.Parameters.AddWithValue("org", id);
        return Assert.IsType<long>(await cmd.ExecuteScalarAsync());
    }

    [Fact]
    public async Task OwnerCleanupRemovesIdleSubjectsAndTenantButNeverActiveQuotasOrOrg()
    {
        var idle = await CreateTenant();
        var active = await CreateTenant();
        await Consume(idle, "ci-idle-A");
        await Consume(idle, "ci-idle-B");
        await Consume(active, "ci-active");

        // A search audit is a separate evidence-access record and must survive
        // maintenance of disposable admission counters, even for idle tenant.
        await using (var auditConn = Owner())
        {
            await auditConn.OpenAsync();
            await using var appendAudit = new NpgsqlCommand("""
                INSERT INTO public.tenant_audit_events(
                    id, organization_id, actor_subject_id, action, occurred_utc)
                VALUES (@id, @org, 'ci-idle-A',
                        'document_imprint_search_performed', now())
                """, auditConn);
            appendAudit.Parameters.AddWithValue("id", Guid.NewGuid());
            appendAudit.Parameters.AddWithValue("org", idle);
            Assert.Equal(1, await appendAudit.ExecuteNonQueryAsync());
        }

        await using (var owner = Owner())
        {
            await owner.OpenAsync();
            foreach (var table in new[] {
                "imprint_search_rate_tenants", "imprint_search_rate_principals"
            })
            {
                await using var age = new NpgsqlCommand(
                    $"UPDATE public.{table} SET window_start = now()-interval '10 minutes' WHERE organization_id=@org",
                    owner);
                age.Parameters.AddWithValue("org", idle);
                await age.ExecuteNonQueryAsync();
            }
        }

        Assert.Equal(2L, await Count(idle, "imprint_search_rate_principals"));
        var removed = await Purge(500);
        Assert.True(removed.Principals >= 2);
        Assert.True(removed.Tenants >= 1);

        Assert.Equal(0L, await Count(idle, "imprint_search_rate_principals"));
        Assert.Equal(0L, await Count(idle, "imprint_search_rate_tenants"));
        Assert.Equal(1L, await Count(active, "imprint_search_rate_principals"));
        Assert.Equal(1L, await Count(active, "imprint_search_rate_tenants"));
        Assert.Equal(1L, await Count(idle, "organizations"));
        Assert.Equal(1L, await Count(idle, "tenant_audit_events"));
        Assert.Equal(1L, await Count(active, "organizations"));

        // The counter can be recreated through the ORIGINAL authenticated
        // admission path; maintenance never disables a tenant or bypasses quota.
        await Consume(idle, "ci-idle-A");
        Assert.Equal(1L, await Count(idle, "imprint_search_rate_principals"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(501)]
    [InlineData(int.MaxValue)]
    public async Task OutOfBoundsBatchIsRejectedBeforeAnyDeletion(int invalid)
    {
        await using var conn = Owner();
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT * FROM public.purge_stale_imprint_search_rate_counters(@batch)", conn);
        cmd.Parameters.AddWithValue("batch", invalid);
        var error = await Assert.ThrowsAsync<PostgresException>(
            async () => await cmd.ExecuteReaderAsync());
        Assert.Equal(PostgresErrorCodes.InvalidParameterValue, error.SqlState);
    }

    [Fact]
    public async Task CleanupCanBeCalledRepeatedlyWithoutExposingSubjectIds()
    {
        var a = await Purge(1);
        var b = await Purge(1);
        Assert.InRange(a.Principals, 0, 1);
        Assert.InRange(b.Tenants, 0, 1);
    }

    [Fact]
    public async Task RuntimeCannotExecuteMaintenanceOrReadItsProtectedRateTables()
    {
        await using var conn = Runtime();
        await conn.OpenAsync();
        await using (var privileges = new NpgsqlCommand("""
            SELECT has_function_privilege(current_user,
                 'public.consume_imprint_search_rate(uuid,text)', 'EXECUTE'),
                   has_function_privilege(current_user,
                 'public.purge_stale_imprint_search_rate_counters(integer)', 'EXECUTE')
            """, conn))
        {
            await using var reader = await privileges.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.True(reader.GetBoolean(0));
            Assert.False(reader.GetBoolean(1));
        }

        await using var cmd = new NpgsqlCommand(
            "SELECT * FROM public.purge_stale_imprint_search_rate_counters(10)", conn);
        var denied = await Assert.ThrowsAsync<PostgresException>(
            async () => await cmd.ExecuteReaderAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denied.SqlState);
    }
}
