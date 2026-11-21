using Npgsql;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>RED-first live PostgreSQL 17, disposable tenant IDs; all replicas share one primary.</summary>
[Collection("SharedSearchQuotaPostgresState")]
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

    // The product SQL function chooses floor(extract(epoch from
    // clock_timestamp())/60), never the app clock or transaction start time.
    // Read this exact PostgreSQL server bucket immediately before AND after
    // each entire test scenario, including its persisted counter assertions.
    private static async Task<long> DatabaseEpochMinuteAsync()
    {
        await using var owner = OwnerConnection();
        await owner.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp()) / 60)::bigint",
            owner);
        return Assert.IsType<long>(await cmd.ExecuteScalarAsync());
    }

    private static async Task<(int TenantHits, long PrincipalHits, int MaxPrincipalHits)>
        RateTotalsAsync(Guid org)
    {
        // Only the separate migration owner may inspect internal quota tables;
        // never enlarge the runtime SQL role to make test observations work.
        await using var owner = OwnerConnection();
        await owner.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT t.hits,
                coalesce((
                    SELECT sum(p.hits)
                      FROM public.imprint_search_rate_principals AS p
                     WHERE p.organization_id = t.organization_id
                ), 0)::bigint,
                coalesce((
                    SELECT max(p.hits)
                      FROM public.imprint_search_rate_principals AS p
                     WHERE p.organization_id = t.organization_id
                ), 0)::integer
              FROM public.imprint_search_rate_tenants AS t
             WHERE t.organization_id = @org
            """, owner);
        cmd.Parameters.AddWithValue("org", org);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        var counts = (
            TenantHits: reader.GetInt32(0),
            PrincipalHits: reader.GetInt64(1),
            MaxPrincipalHits: reader.GetInt32(2));
        Assert.False(await reader.ReadAsync());
        return counts;
    }


    [Fact]
    public async Task TwelvePerPrincipalThenGenericDenialWithoutIncrement()
    {
        var verified = await SearchQuotaServerMinuteEvidence.RunAsync(
            DatabaseEpochMinuteAsync,
            async () =>
            {
                var org = await TenantAsync(); // NEW tenant on each bounded attempt.
                var observed = new (bool Allowed, int Retry)[13];
                for (var i = 0; i < observed.Length; i++)
                    observed[i] = await Consume(org, "verified-ci-admin");
                return new
                {
                    Admissions = observed,
                    Totals = await RateTotalsAsync(org)
                };
            });

        // No assertions are skipped: they apply to the one proven to stay
        // within a single actual PostgreSQL clock_timestamp() epoch-minute.
        Assert.All(verified.Admissions.Take(12),
            result => Assert.Equal((true, 0), result));
        Assert.False(verified.Admissions[12].Allowed);
        Assert.InRange(verified.Admissions[12].Retry, 1, 60);
        Assert.Equal(12, verified.Totals.TenantHits);
        Assert.Equal(12L, verified.Totals.PrincipalHits);
        Assert.Equal(12, verified.Totals.MaxPrincipalHits);
    }


    [Fact]
    public async Task TenantAggregateRestrictsRotatingPrincipalsButNotOtherTenants()
    {
        var verified = await SearchQuotaServerMinuteEvidence.RunAsync(
            DatabaseEpochMinuteAsync,
            async () =>
            {
                var a = await TenantAsync(); // FRESH tenants for every attempt.
                var b = await TenantAsync();
                var admitted = new (bool Allowed, int Retry)[30];
                var index = 0;
                foreach (var actor in new[] { "principal-1", "principal-2", "principal-3" })
                    for (var i = 0; i < 10; i++)
                        admitted[index++] = await Consume(a, actor);

                var denied = await Consume(a, "new-fourth-principal");
                var otherTenant = await Consume(b, "principal-1");
                return new
                {
                    Admitted = admitted,
                    Denied = denied,
                    OtherTenant = otherTenant,
                    A = await RateTotalsAsync(a),
                    B = await RateTotalsAsync(b)
                };
            });

        Assert.All(verified.Admitted,
            admission => Assert.Equal((true, 0), admission));
        Assert.False(verified.Denied.Allowed); // 31st in SAME DB epoch-minute
        Assert.InRange(verified.Denied.Retry, 1, 60);
        Assert.Equal((true, 0), verified.OtherTenant);
        Assert.Equal(30, verified.A.TenantHits);
        Assert.Equal(30L, verified.A.PrincipalHits);
        Assert.Equal(10, verified.A.MaxPrincipalHits);
        Assert.Equal(1, verified.B.TenantHits);
        Assert.Equal(1L, verified.B.PrincipalHits);
    }


    [Fact]
    public async Task SimultaneousSessionsNeverExceedSharedTenantBudget()
    {
        var verified = await SearchQuotaServerMinuteEvidence.RunAsync(
            DatabaseEpochMinuteAsync,
            async () =>
            {
                var org = await TenantAsync();
                // 72 separate SQL sessions with 6 authenticated principals
                // share one PostgreSQL tenant transaction lock (not a .NET lock).
                var admissions = await Task.WhenAll(Enumerable.Range(0, 72).Select(
                    i => Consume(org, "parallel-principal-" + i % 6)));
                return new
                {
                    Admissions = admissions,
                    Totals = await RateTotalsAsync(org)
                };
            });

        Assert.Equal(30, verified.Admissions.Count(x => x.Allowed));
        Assert.All(verified.Admissions.Where(x => !x.Allowed),
            x => Assert.InRange(x.Retry, 1, 60));
        Assert.Equal(30, verified.Totals.TenantHits);
        Assert.Equal(30L, verified.Totals.PrincipalHits);
        Assert.InRange(verified.Totals.MaxPrincipalHits, 1, 12);
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

    [Fact]
    public async Task PreviousDatabaseEpochMinuteExhaustionPermitsFreshMinuteWithoutWaiting()
    {
        var org = await TenantAsync();
        const string actor = "old-minute-actor";
        Assert.Equal((true, 0), await Consume(org, actor));

        // Simulation of the SAME state a real PostgreSQL epoch-minute rollover
        // leaves behind. Only the test migration owner can seed rate tables;
        // ordinary runtime continues through V019 SECURITY DEFINER. No pg_sleep,
        // app clock, time mocking, schema change or SQL grant is involved.
        await using var owner = OwnerConnection();
        await owner.OpenAsync();
        await using var tx = await owner.BeginTransactionAsync();
        DateTime oldTenantWindow;
        DateTime oldActorWindow;
        await using (var tenant = new NpgsqlCommand("""
            UPDATE public.imprint_search_rate_tenants
               SET window_start = pg_catalog.to_timestamp((
                       floor(extract(epoch FROM pg_catalog.clock_timestamp()) / 60) * 60
                   )::double precision) - interval '1 minute',
                   hits = 30
             WHERE organization_id = @org
             RETURNING window_start
            """, owner, tx))
        {
            tenant.Parameters.AddWithValue("org", org);
            oldTenantWindow = Assert.IsType<DateTime>(await tenant.ExecuteScalarAsync());
        }
        await using (var principal = new NpgsqlCommand("""
            UPDATE public.imprint_search_rate_principals
               SET window_start = pg_catalog.to_timestamp((
                       floor(extract(epoch FROM pg_catalog.clock_timestamp()) / 60) * 60
                   )::double precision) - interval '1 minute',
                   hits = 12
             WHERE organization_id = @org AND actor_subject_id = @actor
             RETURNING window_start
            """, owner, tx))
        {
            principal.Parameters.AddWithValue("org", org);
            principal.Parameters.AddWithValue("actor", actor);
            oldActorWindow = Assert.IsType<DateTime>(await principal.ExecuteScalarAsync());
        }
        await tx.CommitAsync();

        // Being exhausted in the PREVIOUS fixed minute must not impose a
        // rolling 60-second ban on the very first request of the NEXT minute.
        Assert.Equal((true, 0), await Consume(org, actor));

        await using var evidence = new NpgsqlCommand("""
            SELECT t.hits, p.hits, t.window_start, p.window_start
              FROM public.imprint_search_rate_tenants AS t
              JOIN public.imprint_search_rate_principals AS p
                ON p.organization_id = t.organization_id
             WHERE t.organization_id = @org AND p.actor_subject_id = @actor
            """, owner);
        evidence.Parameters.AddWithValue("org", org);
        evidence.Parameters.AddWithValue("actor", actor);
        await using var row = await evidence.ExecuteReaderAsync();
        Assert.True(await row.ReadAsync());
        Assert.Equal(1, row.GetInt32(0));
        Assert.Equal(1, row.GetInt32(1));
        var newTenantWindow = row.GetDateTime(2);
        var newActorWindow = row.GetDateTime(3);
        Assert.True(newTenantWindow > oldTenantWindow);
        Assert.True(newActorWindow > oldActorWindow);
        Assert.Equal(newTenantWindow, newActorWindow);
        Assert.False(await row.ReadAsync());
    }

}
