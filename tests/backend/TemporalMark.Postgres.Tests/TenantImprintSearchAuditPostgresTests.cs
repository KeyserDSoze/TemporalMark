using Npgsql;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>V018 live PostgreSQL check constraints. Disposable pilot records, not WORM.</summary>
public sealed class TenantImprintSearchAuditPostgresTests
{
    private static NpgsqlConnection Connection() =>
        new(Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("TEMPORALMARK_TEST_DB is required."));

    [Fact]
    public async Task V018AcceptsMinimalSearchEventAndRejectsAnyReceiptOrPeriodPayload()
    {
        await using var conn = Connection();
        await conn.OpenAsync();
        var org = Guid.NewGuid();
        await using (var bootstrap = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-verified-test-admin')", conn))
        {
            bootstrap.Parameters.AddWithValue("id", org);
            bootstrap.Parameters.AddWithValue("name", "V018 Test " + org.ToString("N"));
            Assert.Equal(org, Assert.IsType<Guid>(await bootstrap.ExecuteScalarAsync()));
        }

        var id = Guid.NewGuid();
        await using (var insert = new NpgsqlCommand("""
            INSERT INTO public.tenant_audit_events
                (id, organization_id, actor_subject_id, action, occurred_utc)
            VALUES (@id, @org, 'ci-verified-test-admin',
                    'document_imprint_search_performed', now())
            """, conn))
        {
            insert.Parameters.AddWithValue("id", id);
            insert.Parameters.AddWithValue("org", org);
            Assert.Equal(1, await insert.ExecuteNonQueryAsync());
        }

        foreach (var payload in new[]
        {
            "receipt_id = gen_random_uuid()",
            "period_from_utc = now() - interval '1 day', period_to_utc_exclusive = now()"
        })
        {
            await using var invalid = new NpgsqlCommand($"""
                INSERT INTO public.tenant_audit_events
                    (id, organization_id, actor_subject_id, action, occurred_utc,
                     receipt_id, period_from_utc, period_to_utc_exclusive)
                SELECT gen_random_uuid(), @org, 'ci-verified-test-admin',
                       'document_imprint_search_performed', now(),
                       { (payload.StartsWith("receipt_id") ? "gen_random_uuid()" : "NULL") },
                       { (payload.StartsWith("receipt_id") ? "NULL" : "now() - interval '1 day'") },
                       { (payload.StartsWith("receipt_id") ? "NULL" : "now()") }
                """, conn);
            invalid.Parameters.AddWithValue("org", org);
            var failure = await Assert.ThrowsAsync<PostgresException>(
                async () => await invalid.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.CheckViolation, failure.SqlState);
        }

        await using (var read = new NpgsqlCommand("""
            SELECT receipt_id IS NULL, period_from_utc IS NULL,
                   period_to_utc_exclusive IS NULL
              FROM public.tenant_audit_events WHERE id = @id
            """, conn))
        {
            read.Parameters.AddWithValue("id", id);
            await using var reader = await read.ExecuteReaderAsync();
            Assert.True(await reader.ReadAsync());
            Assert.True(reader.GetBoolean(0) && reader.GetBoolean(1) && reader.GetBoolean(2));
            Assert.False(await reader.ReadAsync());
        }

        await using var mutate = new NpgsqlCommand(
            "UPDATE public.tenant_audit_events SET actor_subject_id='mutated' WHERE id=@id", conn);
        mutate.Parameters.AddWithValue("id", id);
        var denied = await Assert.ThrowsAsync<PostgresException>(
            async () => await mutate.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.RaiseException, denied.SqlState);
    }
}
