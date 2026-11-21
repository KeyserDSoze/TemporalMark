using Npgsql;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// ADR 0099 / #133, real PostgreSQL 17 first: prove a runtime login can be
/// distinguished from owner, privileged operator and independent approver.
/// Never execute CREATE/GRANT/REVOKE/SET ROLE or mutate data in this probe.
/// </summary>
public sealed class PostgresRuntimePrivilegePreflightTests
{
    private static NpgsqlConnection Connection(string key) => new(
        Environment.GetEnvironmentVariable(key)
            ?? throw new InvalidOperationException("Required local PostgreSQL CI fixture is unavailable"));

    private static NpgsqlConnection Runtime() =>
        Connection("TEMPORALMARK_RUNTIME_TEST_DB");

    private static NpgsqlConnection Owner() =>
        Connection("TEMPORALMARK_TEST_DB");

    private static NpgsqlConnection Provisioner() =>
        Connection("TEMPORALMARK_PROVISIONING_TEST_DB");

    private static NpgsqlConnection Approver() =>
        Connection("TEMPORALMARK_APPROVER_TEST_DB");

    private static async Task<long> MigrationCountAsync(NpgsqlConnection connection)
    {
        await using var cmd = new NpgsqlCommand("SELECT count(*) FROM public.schema_migrations", connection);
        return Assert.IsType<long>(await cmd.ExecuteScalarAsync());
    }

    [Fact]
    public async Task LocalRuntimeWithExpectedReadOnlyAclCanPassWithoutModifyingMigrations()
    {
        // The ordinary runtime login must NOT be granted access to the
        // migration-owner ledger merely to test read-only behavior.
        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));
        await using var c = Runtime();
        await c.OpenAsync();
        await PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark_api", CancellationToken.None);
        Assert.Equal(20L, await MigrationCountAsync(owner));
    }

    // #141 / ADR 0106: genuine PG17 tests, without touching the shared runtime
    // group or any migrated table. Each independently generated login has
    // correct runtime membership first, and gets exactly ONE extra grant.
    // A wrong ACL must fail pre-listen instead of being misclassified WORM.
    [Theory]
    [InlineData("timestamp_registry", "UPDATE")]
    [InlineData("timestamp_registry", "DELETE")]
    [InlineData("timestamp_registry", "TRUNCATE")]
    [InlineData("timestamp_registry", "TRIGGER")]
    [InlineData("timestamp_registry", "REFERENCES")]
    [InlineData("timestamp_registry", "UPDATE (validation_state)")]
    [InlineData("timestamp_registry", "REFERENCES (id)")]
    [InlineData("tenant_audit_events", "UPDATE")]
    [InlineData("tenant_audit_events", "DELETE")]
    [InlineData("tenant_audit_events", "TRUNCATE")]
    [InlineData("tenant_audit_events", "TRIGGER")]
    [InlineData("tenant_audit_events", "REFERENCES")]
    [InlineData("tenant_audit_events", "UPDATE (action)")]
    [InlineData("tenant_audit_events", "REFERENCES (id)")]
    public async Task AdditionalEvidenceMutationGrantMustRejectOtherwiseSafeRuntimeLogin(
        string tableName, string privilege)
    {
        // SQL identifiers and privilege names are fixed InlineData literals;
        // the per-test role/password use only safely generated ASCII hex.
        var role = "tm_acl_" + Guid.NewGuid().ToString("N");
        var password = "test-" + Guid.NewGuid().ToString("N");
        var roleCreated = false;
        var groupGranted = false;
        var extraGranted = false;
        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));
        var connectionString = new NpgsqlConnectionStringBuilder(owner.ConnectionString)
        {
            Username = role,
            Password = password,
            // Every test generates a unique username. Never retain a pooled
            // backend session after teardown; PG17 runner has finite slots.
            Pooling = false
        }.ConnectionString;

        async Task ExecOwnerAsync(string commandText)
        {
            await using var command = new NpgsqlCommand(commandText, owner);
            await command.ExecuteNonQueryAsync();
        }

        try
        {
            await ExecOwnerAsync($"CREATE ROLE {role} LOGIN INHERIT PASSWORD '{password}'");
            roleCreated = true;
            await ExecOwnerAsync($"GRANT temporalmark_runtime_group TO {role}");
            groupGranted = true;

            // Baseline proves this disposable role is a valid runtime identity:
            // a denial after the extra grant is actually attributable to it.
            await using (var approved = new NpgsqlConnection(connectionString))
            {
                await approved.OpenAsync();
                await PostgresRuntimePrivilegePreflight.VerifyAsync(
                    approved, role, CancellationToken.None);
            }

            await ExecOwnerAsync($"GRANT {privilege} ON TABLE public.{tableName} TO {role}");
            extraGranted = true;
            await using (var unsafeSession = new NpgsqlConnection(connectionString))
            {
                await unsafeSession.OpenAsync();
                var denial = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    PostgresRuntimePrivilegePreflight.VerifyAsync(
                        unsafeSession, role, CancellationToken.None));
                Assert.Null(denial.InnerException);
                Assert.DoesNotContain(role, denial.ToString());
                Assert.DoesNotContain(password, denial.ToString());
            }
        }
        finally
        {
            // Teardown runs on both RED failures and GREEN. Do not leak any
            // extra grant/role into a later test or a shared runtime login.
            if (extraGranted)
                await ExecOwnerAsync($"REVOKE {privilege} ON TABLE public.{tableName} FROM {role}");
            if (groupGranted)
                await ExecOwnerAsync($"REVOKE temporalmark_runtime_group FROM {role}");
            if (roleCreated)
                await ExecOwnerAsync($"DROP ROLE {role}");
        }

        Assert.Equal(20L, await MigrationCountAsync(owner));
    }

    // #142 / ADR 0107: organizational invariants require more than denying
    // table-level UPDATE. Each distinct test login must pass baseline first;
    // only that disposable login receives one deliberately unsafe grant.
    [Theory]
    [InlineData("organizations", "UPDATE (display_name)")]
    [InlineData("organizations", "REFERENCES")]
    [InlineData("organizations", "REFERENCES (id)")]
    [InlineData("organizations", "TRIGGER")]
    [InlineData("organization_memberships", "UPDATE (role)")]
    [InlineData("organization_memberships", "REFERENCES")]
    [InlineData("organization_memberships", "REFERENCES (organization_id)")]
    [InlineData("organization_memberships", "TRIGGER")]
    public async Task ColumnMutationOrReferenceOrTriggerGrantMustNotPassTenantPreflight(
        string tableName, string privilege)
    {
        // Table/column names come only from fixed compile-time InlineData,
        // and generated role/password contain only safe ASCII hex characters.
        var role = "tm_orgacl_" + Guid.NewGuid().ToString("N");
        var password = "test-" + Guid.NewGuid().ToString("N");
        var roleCreated = false;
        var membershipGranted = false;
        var unsafeGrantCreated = false;
        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));

        var loginConnectionString = new NpgsqlConnectionStringBuilder(owner.ConnectionString)
        {
            Username = role,
            Password = password,
            // Every test generates a unique username. Never retain a pooled
            // backend session after teardown; PG17 runner has finite slots.
            Pooling = false
        }.ConnectionString;

        async Task RunOwnerAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, owner);
            await command.ExecuteNonQueryAsync();
        }

        try
        {
            await RunOwnerAsync($"CREATE ROLE {role} LOGIN INHERIT PASSWORD '{password}'");
            roleCreated = true;
            await RunOwnerAsync($"GRANT temporalmark_runtime_group TO {role}");
            membershipGranted = true;

            await using (var baseline = new NpgsqlConnection(loginConnectionString))
            {
                await baseline.OpenAsync();
                await PostgresRuntimePrivilegePreflight.VerifyAsync(
                    baseline, role, CancellationToken.None);
            }

            await RunOwnerAsync($"GRANT {privilege} ON TABLE public.{tableName} TO {role}");
            unsafeGrantCreated = true;
            await using (var overprivileged = new NpgsqlConnection(loginConnectionString))
            {
                await overprivileged.OpenAsync();
                var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    PostgresRuntimePrivilegePreflight.VerifyAsync(
                        overprivileged, role, CancellationToken.None));
                Assert.Null(exception.InnerException);
                Assert.DoesNotContain(role, exception.ToString());
                Assert.DoesNotContain(password, exception.ToString());
            }
        }
        finally
        {
            // Teardown even when a RED assertion fails. No grants to shared
            // production-like groups and no table or migration DML/DDL.
            if (unsafeGrantCreated)
                await RunOwnerAsync($"REVOKE {privilege} ON TABLE public.{tableName} FROM {role}");
            if (membershipGranted)
                await RunOwnerAsync($"REVOKE temporalmark_runtime_group FROM {role}");
            if (roleCreated)
                await RunOwnerAsync($"DROP ROLE {role}");
        }

        Assert.Equal(20L, await MigrationCountAsync(owner));
    }

    // #146 / ADR 0111: V019 SQL quota tables are owned by the migration
    // principal; the API runtime may EXECUTE the approved SECURITY DEFINER
    // quota function, but MUST NOT directly SELECT PII actor subjects or
    // alter the quota state. PG17 also supports column-only ACL misgrants.
    // Every test role first passes the candidate preflight and receives
    // exactly one unsafe privilege that must become a generic startup denial.
    [Theory]
    [InlineData("imprint_search_rate_tenants", "SELECT")]
    [InlineData("imprint_search_rate_tenants", "SELECT (organization_id)")]
    [InlineData("imprint_search_rate_tenants", "INSERT")]
    [InlineData("imprint_search_rate_tenants", "INSERT (organization_id)")]
    [InlineData("imprint_search_rate_tenants", "UPDATE (hits)")]
    [InlineData("imprint_search_rate_tenants", "DELETE")]
    [InlineData("imprint_search_rate_tenants", "TRUNCATE")]
    [InlineData("imprint_search_rate_tenants", "REFERENCES (organization_id)")]
    [InlineData("imprint_search_rate_tenants", "TRIGGER")]
    [InlineData("imprint_search_rate_principals", "SELECT")]
    [InlineData("imprint_search_rate_principals", "SELECT (actor_subject_id)")]
    [InlineData("imprint_search_rate_principals", "INSERT")]
    [InlineData("imprint_search_rate_principals", "INSERT (actor_subject_id)")]
    [InlineData("imprint_search_rate_principals", "UPDATE (hits)")]
    [InlineData("imprint_search_rate_principals", "DELETE")]
    [InlineData("imprint_search_rate_principals", "TRUNCATE")]
    [InlineData("imprint_search_rate_principals", "REFERENCES (organization_id)")]
    [InlineData("imprint_search_rate_principals", "TRIGGER")]
    public async Task AdditionalDirectQuotaTableGrantMustNotPassEntraRuntimePreflight(
        string tableName, string privilege)
    {
        // SQL identifiers/privileges are fixed test InlineData, and unique
        // disposable LOGIN names/passwords contain only safe ASCII hex.
        var role = "tm_quotaacl_" + Guid.NewGuid().ToString("N");
        var password = "test-" + Guid.NewGuid().ToString("N");
        var roleCreated = false;
        var memberGranted = false;
        var overGrantApplied = false;

        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));
        var loginConnectionString = new NpgsqlConnectionStringBuilder(owner.ConnectionString)
        {
            Username = role,
            Password = password,
            // The unique login must not leave one Npgsql pool per test
            // consuming real PostgreSQL 17 CI connection slots.
            Pooling = false
        }.ConnectionString;

        async Task RunOwnerAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, owner);
            await command.ExecuteNonQueryAsync();
        }

        try
        {
            await RunOwnerAsync($"CREATE ROLE {role} LOGIN INHERIT PASSWORD '{password}'");
            roleCreated = true;
            await RunOwnerAsync($"GRANT temporalmark_runtime_group TO {role}");
            memberGranted = true;

            // Without any extra direct quota table ACL, the role is an
            // otherwise-valid runtime principal: the baseline must PASS.
            await using (var baseline = new NpgsqlConnection(loginConnectionString))
            {
                await baseline.OpenAsync();
                await PostgresRuntimePrivilegePreflight.VerifyAsync(
                    baseline, role, CancellationToken.None);
            }

            // Grant exactly ONE table-wide or single-column privilege, never
            // to the common runtime group; no quota counters are modified.
            await RunOwnerAsync($"GRANT {privilege} ON TABLE public.{tableName} TO {role}");
            overGrantApplied = true;

            await using (var overprivileged = new NpgsqlConnection(loginConnectionString))
            {
                await overprivileged.OpenAsync();
                var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    PostgresRuntimePrivilegePreflight.VerifyAsync(
                        overprivileged, role, CancellationToken.None));
                Assert.Null(error.InnerException);
                Assert.DoesNotContain(role, error.ToString());
                Assert.DoesNotContain(password, error.ToString());
                Assert.DoesNotContain("ConnectionStrings", error.ToString());
            }
        }
        finally
        {
            // Teardown even during expected RED. Test-only owner GRANT is
            // reverted before membership/drop, preserving V001–V020 bytes,
            // shared runtime role privileges and live quota counter rows.
            if (overGrantApplied)
                await RunOwnerAsync($"REVOKE {privilege} ON TABLE public.{tableName} FROM {role}");
            if (memberGranted)
                await RunOwnerAsync($"REVOKE temporalmark_runtime_group FROM {role}");
            if (roleCreated)
                await RunOwnerAsync($"DROP ROLE {role}");
        }

        Assert.Equal(20L, await MigrationCountAsync(owner));
    }

    // #147 / ADR 0112: PostgreSQL role membership alone cannot detect
    // one mistaken direct EXECUTE GRANT on a provisioner/approver/registrar
    // SECURITY DEFINER function or an explicitly owner-only routine.
    // These tests inspect rights only: NEVER invoke a privileged routine.
    [Theory]
    [InlineData("request_enrollment(uuid,text,text,text,text,char(64),char(64))")]
    [InlineData("approve_enrollment(uuid,text,text,text,text,text,char(64))")]
    [InlineData("complete_enrollment(uuid,text,text,text,text,char(64),char(64))")]
    [InlineData("read_pending_enrollment(uuid,text,text)")]
    [InlineData("issue_reviewer_registration_intent(text,text,text,text,text)")]
    [InlineData("record_unapproved_mds_checkpoint_candidate(text,text,bigint,text,text,integer,text)")]
    [InlineData("purge_stale_imprint_search_rate_counters(integer)")]
    public async Task DirectPrivilegedFunctionExecuteGrantMustNotPassEntraRuntimePreflight(
        string fixedFunctionIdentity)
    {
        // The function identities are fixed test InlineData from migrations.
        // Distinct generated SQL role/password use only ASCII hex; NEVER add
        // function permissions to shared runtime/approver/provisioner groups.
        var role = "tm_funcacl_" + Guid.NewGuid().ToString("N");
        var password = "test-" + Guid.NewGuid().ToString("N");
        var created = false;
        var membershipGranted = false;
        var executeGranted = false;

        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));
        var connectionString = new NpgsqlConnectionStringBuilder(owner.ConnectionString)
        {
            Username = role,
            Password = password,
            // Unique disposable test credentials must not retain connection
            // pool slots across the PG17 integration suite.
            Pooling = false
        }.ConnectionString;

        async Task RunOwnerAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, owner);
            await command.ExecuteNonQueryAsync();
        }

        try
        {
            await RunOwnerAsync($"CREATE ROLE {role} LOGIN INHERIT PASSWORD '{password}'");
            created = true;
            await RunOwnerAsync($"GRANT temporalmark_runtime_group TO {role}");
            membershipGranted = true;

            await using (var baseline = new NpgsqlConnection(connectionString))
            {
                await baseline.OpenAsync();
                // Prove this generated runtime LOGIN passes current preflight
                // before any extra privilege, preventing false-positive RED.
                await PostgresRuntimePrivilegePreflight.VerifyAsync(
                    baseline, role, CancellationToken.None);
            }

            await RunOwnerAsync(
                $"GRANT EXECUTE ON FUNCTION public.{fixedFunctionIdentity} TO {role}");
            executeGranted = true;

            await using (var elevated = new NpgsqlConnection(connectionString))
            {
                await elevated.OpenAsync();
                var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    PostgresRuntimePrivilegePreflight.VerifyAsync(
                        elevated, role, CancellationToken.None));
                Assert.Null(error.InnerException);
                Assert.DoesNotContain(role, error.ToString());
                Assert.DoesNotContain(password, error.ToString());
            }
        }
        finally
        {
            // Teardown is mandatory even when old source fails RED; do not
            // leave function grants or LOGIN roles for later tests.
            if (executeGranted)
                await RunOwnerAsync(
                    $"REVOKE EXECUTE ON FUNCTION public.{fixedFunctionIdentity} FROM {role}");
            if (membershipGranted)
                await RunOwnerAsync($"REVOKE temporalmark_runtime_group FROM {role}");
            if (created)
                await RunOwnerAsync($"DROP ROLE {role}");
        }

        Assert.Equal(20L, await MigrationCountAsync(owner));
    }

    [Fact]
    public async Task DatabaseOwnerOrSuperuserIsRejectedEvenIfConfiguredAsExpectedLogin()
    {
        await using var c = Owner();
        await c.OpenAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark", CancellationToken.None));
        Assert.Null(ex.InnerException);
        Assert.DoesNotContain("Password=", ex.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(20L, await MigrationCountAsync(c));
    }

    [Fact]
    public async Task ProvisionerLoginIsRejectedDespiteValidSqlLogin()
    {
        await using var c = Provisioner();
        await c.OpenAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark_provisioner",
                CancellationToken.None));
        Assert.Null(ex.InnerException);
        Assert.DoesNotContain("local-provisioner-only", ex.ToString());
    }

    [Fact]
    public async Task IndependentApproverLoginIsRejectedDespiteValidSqlLogin()
    {
        await using var c = Approver();
        await c.OpenAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark_approver",
                CancellationToken.None));
        Assert.Null(ex.InnerException);
        Assert.DoesNotContain("local-approver-only", ex.ToString());
    }

    [Theory]
    [InlineData("temporalmark_provisioner")]
    [InlineData("temporalmark_approver")]
    [InlineData("temporalmark")]
    public async Task RuntimeSessionCannotClaimAnotherExpectedDbLogin(string expectedLogin)
    {
        await using var c = Runtime();
        await c.OpenAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, expectedLogin, CancellationToken.None));
        Assert.Null(ex.InnerException);
        Assert.DoesNotContain(expectedLogin, ex.ToString());
    }

    [Fact]
    public async Task ClosedConnectionCannotBeOpenedByThePreflight()
    {
        await using var c = Runtime();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark_api",
                CancellationToken.None));
        Assert.Null(ex.InnerException);
        Assert.Equal(System.Data.ConnectionState.Closed, c.State);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("a;DROP ROLE")]
    [InlineData("a\nsecret")]
    public async Task RejectsUnapprovedPrincipalSyntaxWithoutOpeningAConnection(string login)
    {
        await using var c = Runtime();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, login, CancellationToken.None));
        Assert.Equal(System.Data.ConnectionState.Closed, c.State);
    }

    [Fact]
    public async Task ExplicitCancellationIsPreservedWithoutRunningAnySql()
    {
        await using var c = Runtime();
        await c.OpenAsync();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark_api", cancelled.Token));
        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));
    }

    [Fact]
    public async Task NullConnectionDoesNotAttemptToDiscoverAnyAmbientCredentials()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(null!, "temporalmark_api",
                CancellationToken.None));
    }
}
