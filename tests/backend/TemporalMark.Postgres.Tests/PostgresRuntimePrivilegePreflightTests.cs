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

    // #149 / ADR 0114: V006 reviewer enrollment requests and V012 unsigned
    // decision challenge rows must stay inaccessible to the API runtime.
    // Never read or mutate domain data: test GRANT inspection only.
    [Theory]
    [InlineData("organization_enrollment_requests", "SELECT")]
    [InlineData("organization_enrollment_requests", "SELECT (operator_subject)")]
    [InlineData("organization_enrollment_requests", "INSERT")]
    [InlineData("organization_enrollment_requests", "INSERT (id)")]
    [InlineData("organization_enrollment_requests", "UPDATE (approved_utc)")]
    [InlineData("organization_enrollment_requests", "DELETE")]
    [InlineData("organization_enrollment_requests", "TRUNCATE")]
    [InlineData("organization_enrollment_requests", "REFERENCES (id)")]
    [InlineData("organization_enrollment_requests", "TRIGGER")]
    [InlineData("organization_decision_challenges", "SELECT")]
    [InlineData("organization_decision_challenges", "SELECT (nonce)")]
    [InlineData("organization_decision_challenges", "INSERT")]
    [InlineData("organization_decision_challenges", "INSERT (id)")]
    [InlineData("organization_decision_challenges", "UPDATE (nonce)")]
    [InlineData("organization_decision_challenges", "DELETE")]
    [InlineData("organization_decision_challenges", "TRUNCATE")]
    [InlineData("organization_decision_challenges", "REFERENCES (id)")]
    [InlineData("organization_decision_challenges", "TRIGGER")]
    public async Task ReviewerEnrollmentOrChallengeTableOvergrantMustFailEntraRuntimePreflight(
        string fixedTable, string fixedPrivilege)
    {
        // Identifiers/privileges are fixed InlineData, not caller input.
        // Per-case LOGIN/password are generated ASCII and never persisted.
        var role = "tm_reviewacl_" + Guid.NewGuid().ToString("N");
        var password = "test-" + Guid.NewGuid().ToString("N");
        var roleCreated = false;
        var membershipGranted = false;
        var grantApplied = false;

        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));
        var testConnectionString = new NpgsqlConnectionStringBuilder(owner.ConnectionString)
        {
            Username = role,
            Password = password,
            // Avoid PG17 slot exhaustion from one Npgsql pool per generated LOGIN.
            Pooling = false
        }.ConnectionString;

        async Task OwnerExecuteAsync(string sql)
        {
            await using var cmd = new NpgsqlCommand(sql, owner);
            await cmd.ExecuteNonQueryAsync();
        }

        try
        {
            await OwnerExecuteAsync($"CREATE ROLE {role} LOGIN INHERIT PASSWORD '{password}'");
            roleCreated = true;
            await OwnerExecuteAsync($"GRANT temporalmark_runtime_group TO {role}");
            membershipGranted = true;

            // Confirm baseline valid SQL runtime identity before the extra GRANT.
            await using (var baseline = new NpgsqlConnection(testConnectionString))
            {
                await baseline.OpenAsync();
                await PostgresRuntimePrivilegePreflight.VerifyAsync(
                    baseline, role, CancellationToken.None);
            }

            await OwnerExecuteAsync($"GRANT {fixedPrivilege} ON TABLE public.{fixedTable} TO {role}");
            grantApplied = true;

            await using (var overprivileged = new NpgsqlConnection(testConnectionString))
            {
                await overprivileged.OpenAsync();
                var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    PostgresRuntimePrivilegePreflight.VerifyAsync(
                        overprivileged, role, CancellationToken.None));
                Assert.Null(ex.InnerException);
                Assert.DoesNotContain(role, ex.ToString());
                Assert.DoesNotContain(password, ex.ToString());
                Assert.DoesNotContain("ConnectionStrings", ex.ToString());
            }
        }
        finally
        {
            // Even on intentional RED, cleanup cannot leave an unsafe SQL
            // grant, pool or test-only role in the shared PG17 fixture.
            if (grantApplied)
                await OwnerExecuteAsync(
                    $"REVOKE {fixedPrivilege} ON TABLE public.{fixedTable} FROM {role}");
            if (membershipGranted)
                await OwnerExecuteAsync($"REVOKE temporalmark_runtime_group FROM {role}");
            if (roleCreated)
                await OwnerExecuteAsync($"DROP ROLE {role}");
        }

        Assert.Equal(20L, await MigrationCountAsync(owner));
    }

    // #152 / ADR 0117: V017 unapproved MDS/CRL candidate tables and
    // append-only-by-trigger event ID sequence are migration-owner only.
    // No candidate data reads/writes and no nextval/currval/setval calls.
    [Theory]
    [InlineData("mds_unapproved_candidate_checkpoints", "SELECT", false)]
    [InlineData("mds_unapproved_candidate_checkpoints", "SELECT (signed_evidence_sha256)", false)]
    [InlineData("mds_unapproved_candidate_checkpoints", "INSERT", false)]
    [InlineData("mds_unapproved_candidate_checkpoints", "INSERT (candidate_kind)", false)]
    [InlineData("mds_unapproved_candidate_checkpoints", "UPDATE (candidate_serial)", false)]
    [InlineData("mds_unapproved_candidate_checkpoints", "REFERENCES (issuer_key_sha256)", false)]
    [InlineData("mds_unapproved_candidate_checkpoints", "DELETE", false)]
    [InlineData("mds_unapproved_candidate_checkpoints", "TRUNCATE", false)]
    [InlineData("mds_unapproved_candidate_checkpoints", "TRIGGER", false)]
    [InlineData("mds_unapproved_candidate_events", "SELECT", false)]
    [InlineData("mds_unapproved_candidate_events", "SELECT (signed_evidence_sha256)", false)]
    [InlineData("mds_unapproved_candidate_events", "INSERT", false)]
    [InlineData("mds_unapproved_candidate_events", "INSERT (candidate_kind)", false)]
    [InlineData("mds_unapproved_candidate_events", "UPDATE (candidate_serial)", false)]
    [InlineData("mds_unapproved_candidate_events", "REFERENCES (event_id)", false)]
    [InlineData("mds_unapproved_candidate_events", "DELETE", false)]
    [InlineData("mds_unapproved_candidate_events", "TRUNCATE", false)]
    [InlineData("mds_unapproved_candidate_events", "TRIGGER", false)]
    [InlineData("mds_unapproved_candidate_events_event_id_seq", "USAGE", true)]
    [InlineData("mds_unapproved_candidate_events_event_id_seq", "SELECT", true)]
    [InlineData("mds_unapproved_candidate_events_event_id_seq", "UPDATE", true)]
    public async Task UnapprovedMdsCandidateTableOrSequenceOvergrantMustRejectRuntimePreflight(
        string fixedObjectName, string fixedPrivilege, bool isSequence)
    {
        // Object/privilege SQL snippets are only fixed compile-time InlineData.
        // Never use a shared LOGIN, shared group grant or migrated table data.
        var role = "tm_mdsacl_" + Guid.NewGuid().ToString("N");
        var password = "test-" + Guid.NewGuid().ToString("N");
        var roleCreated = false;
        var runtimeMembershipGranted = false;
        var extraGrantApplied = false;
        var sqlObjectType = isSequence ? "SEQUENCE" : "TABLE";

        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));

        var testConnectionString = new NpgsqlConnectionStringBuilder(owner.ConnectionString)
        {
            Username = role,
            Password = password,
            Pooling = false // Prevent temporary LOGIN pools exhausting PG17 slots.
        }.ConnectionString;

        async Task OwnerExecuteAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, owner);
            await command.ExecuteNonQueryAsync();
        }

        try
        {
            await OwnerExecuteAsync($"CREATE ROLE {role} LOGIN INHERIT PASSWORD '{password}'");
            roleCreated = true;
            await OwnerExecuteAsync($"GRANT temporalmark_runtime_group TO {role}");
            runtimeMembershipGranted = true;

            await using (var baseline = new NpgsqlConnection(testConnectionString))
            {
                await baseline.OpenAsync();
                await PostgresRuntimePrivilegePreflight.VerifyAsync(
                    baseline, role, CancellationToken.None);
            }

            // Grant exactly one effective table/column or sequence privilege,
            // never touch shared group nor use the sequence or read candidates.
            await OwnerExecuteAsync(
                $"GRANT {fixedPrivilege} ON {sqlObjectType} public.{fixedObjectName} TO {role}");
            extraGrantApplied = true;

            await using (var overprivileged = new NpgsqlConnection(testConnectionString))
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
            // Cleanup even when expected RED assertion fails. No persisted
            // candidate mutation, sequence movement or leaked SQL test LOGIN.
            if (extraGrantApplied)
                await OwnerExecuteAsync(
                    $"REVOKE {fixedPrivilege} ON {sqlObjectType} public.{fixedObjectName} FROM {role}");
            if (runtimeMembershipGranted)
                await OwnerExecuteAsync($"REVOKE temporalmark_runtime_group FROM {role}");
            if (roleCreated)
                await OwnerExecuteAsync($"DROP ROLE {role}");
        }

        Assert.Equal(20L, await MigrationCountAsync(owner));
    }

    // #151 / ADR 0116: V010 replay-proof hashes and V013 owner-controlled
    // unsigned registrar nonces/RP policy must never become runtime SQL ACLs.
    // This test inspects GRANTs only; no customer rows or routines are touched.
    [Theory]
    [InlineData("organization_reviewer_decision_proofs", "SELECT")]
    [InlineData("organization_reviewer_decision_proofs", "SELECT (token_sha256)")]
    [InlineData("organization_reviewer_decision_proofs", "INSERT")]
    [InlineData("organization_reviewer_decision_proofs", "INSERT (token_sha256)")]
    [InlineData("organization_reviewer_decision_proofs", "UPDATE (decision)")]
    [InlineData("organization_reviewer_decision_proofs", "REFERENCES (request_id)")]
    [InlineData("organization_reviewer_decision_proofs", "DELETE")]
    [InlineData("organization_reviewer_decision_proofs", "TRUNCATE")]
    [InlineData("organization_reviewer_decision_proofs", "TRIGGER")]
    [InlineData("reviewer_registration_intents", "SELECT")]
    [InlineData("reviewer_registration_intents", "SELECT (nonce)")]
    [InlineData("reviewer_registration_intents", "INSERT")]
    [InlineData("reviewer_registration_intents", "INSERT (id)")]
    [InlineData("reviewer_registration_intents", "UPDATE (nonce)")]
    [InlineData("reviewer_registration_intents", "REFERENCES (id)")]
    [InlineData("reviewer_registration_intents", "DELETE")]
    [InlineData("reviewer_registration_intents", "TRUNCATE")]
    [InlineData("reviewer_registration_intents", "TRIGGER")]
    [InlineData("reviewer_registration_rp_policies", "SELECT")]
    [InlineData("reviewer_registration_rp_policies", "SELECT (trusted_origin)")]
    [InlineData("reviewer_registration_rp_policies", "INSERT")]
    [InlineData("reviewer_registration_rp_policies", "INSERT (identity_issuer)")]
    [InlineData("reviewer_registration_rp_policies", "UPDATE (trusted_origin)")]
    [InlineData("reviewer_registration_rp_policies", "REFERENCES (rp_id)")]
    [InlineData("reviewer_registration_rp_policies", "DELETE")]
    [InlineData("reviewer_registration_rp_policies", "TRUNCATE")]
    [InlineData("reviewer_registration_rp_policies", "TRIGGER")]
    public async Task ReviewerReplayOrRegistrarPolicyOvergrantMustFailEntraRuntimePreflight(
        string fixedTable, string fixedGrant)
    {
        // All table/column/privilege literals are fixed InlineData, never
        // HTTP input. Distinct disposable LOGIN and password per test case.
        var login = "tm_rproofacl_" + Guid.NewGuid().ToString("N");
        var password = "test-" + Guid.NewGuid().ToString("N");
        var loginCreated = false;
        var runtimeGroupGranted = false;
        var unsafeGrantApplied = false;

        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));
        var isolatedConnectionString = new NpgsqlConnectionStringBuilder(owner.ConnectionString)
        {
            Username = login,
            Password = password,
            Pooling = false // Avoid one persistent Npgsql pool per PG17 test role.
        }.ConnectionString;

        async Task OwnerExecuteAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, owner);
            await command.ExecuteNonQueryAsync();
        }

        try
        {
            await OwnerExecuteAsync($"CREATE ROLE {login} LOGIN INHERIT PASSWORD '{password}'");
            loginCreated = true;
            await OwnerExecuteAsync($"GRANT temporalmark_runtime_group TO {login}");
            runtimeGroupGranted = true;

            // The otherwise valid runtime SQL identity must pass baseline.
            await using (var baseline = new NpgsqlConnection(isolatedConnectionString))
            {
                await baseline.OpenAsync();
                await PostgresRuntimePrivilegePreflight.VerifyAsync(
                    baseline, login, CancellationToken.None);
            }

            await OwnerExecuteAsync($"GRANT {fixedGrant} ON TABLE public.{fixedTable} TO {login}");
            unsafeGrantApplied = true;
            await using (var unsafeLogin = new NpgsqlConnection(isolatedConnectionString))
            {
                await unsafeLogin.OpenAsync();
                var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    PostgresRuntimePrivilegePreflight.VerifyAsync(
                        unsafeLogin, login, CancellationToken.None));
                Assert.Null(ex.InnerException);
                Assert.DoesNotContain(login, ex.ToString());
                Assert.DoesNotContain(password, ex.ToString());
                Assert.DoesNotContain("ConnectionStrings", ex.ToString());
            }
        }
        finally
        {
            // Cleanup executes even when the intentionally RED denial fails.
            // Never modify shared runtime group ACLs or any migrated table rows.
            if (unsafeGrantApplied)
                await OwnerExecuteAsync(
                    $"REVOKE {fixedGrant} ON TABLE public.{fixedTable} FROM {login}");
            if (runtimeGroupGranted)
                await OwnerExecuteAsync($"REVOKE temporalmark_runtime_group FROM {login}");
            if (loginCreated)
                await OwnerExecuteAsync($"DROP ROLE {login}");
        }

        Assert.Equal(20L, await MigrationCountAsync(owner));
    }

    // #150 / ADR 0115: role attributes of an arbitrary SET-able group role
    // are NOT inherited onto current_user, yet SET ROLE can enable them.
    // Test catalog role reachability only; NEVER execute SET ROLE.
    [Theory]
    [InlineData("SUPERUSER", false)]
    [InlineData("CREATEDB", false)]
    [InlineData("CREATEROLE", false)]
    [InlineData("REPLICATION", false)]
    [InlineData("BYPASSRLS", false)]
    [InlineData("CREATEDB", true)]
    [InlineData("BYPASSRLS", true)]
    public async Task ElevatedNoLoginRoleMembershipMustFailEntraRuntimePreflight(
        string fixedElevatedAttribute, bool useIntermediateGroup)
    {
        // All role identifiers use generated ASCII hex; the elevated attribute
        // is one of seven compile-time InlineData literals, never external input.
        var discriminator = Guid.NewGuid().ToString("N");
        var login = "tm_privlogin_" + discriminator;
        var elevatedRole = "tm_privrole_" + discriminator;
        var bridgeRole = "tm_privbridge_" + discriminator;
        var password = "test-" + Guid.NewGuid().ToString("N");
        var loginCreated = false;
        var runtimeGroupGranted = false;
        var elevatedCreated = false;
        var bridgeCreated = false;
        var elevatedGranted = false;
        var bridgeGranted = false;

        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));
        var testConnectionString = new NpgsqlConnectionStringBuilder(owner.ConnectionString)
        {
            Username = login,
            Password = password,
            // Unique SQL LOGIN per case must not consume permanent PG17 pool slots.
            Pooling = false
        }.ConnectionString;

        async Task OwnerExecuteAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, owner);
            await command.ExecuteNonQueryAsync();
        }

        try
        {
            await OwnerExecuteAsync($"CREATE ROLE {login} LOGIN INHERIT PASSWORD '{password}'");
            loginCreated = true;
            await OwnerExecuteAsync($"GRANT temporalmark_runtime_group TO {login}");
            runtimeGroupGranted = true;

            // Before privileged membership, this is an independently valid
            // least-privilege API runtime LOGIN and must pass the current gate.
            await using (var baseline = new NpgsqlConnection(testConnectionString))
            {
                await baseline.OpenAsync();
                await PostgresRuntimePrivilegePreflight.VerifyAsync(
                    baseline, login, CancellationToken.None);
            }

            // CI-only PostgreSQL superuser owns these ephemeral roles; never
            // change actual runtime, provisioner, reviewer or migrated grants.
            await OwnerExecuteAsync($"CREATE ROLE {elevatedRole} NOLOGIN {fixedElevatedAttribute}");
            elevatedCreated = true;

            if (useIntermediateGroup)
            {
                await OwnerExecuteAsync($"CREATE ROLE {bridgeRole} NOLOGIN");
                bridgeCreated = true;
                await OwnerExecuteAsync($"GRANT {bridgeRole} TO {login} WITH SET TRUE");
                bridgeGranted = true;
            }

            // Grant exactly one SET-able privileged role, directly or via a
            // single NOLOGIN bridge. No actual SET ROLE or privileged operation.
            var holder = useIntermediateGroup ? bridgeRole : login;
            await OwnerExecuteAsync($"GRANT {elevatedRole} TO {holder} WITH SET TRUE");
            elevatedGranted = true;

            await using (var overprivileged = new NpgsqlConnection(testConnectionString))
            {
                await overprivileged.OpenAsync();
                // PG17 catalog inquiry proves the dangerous role is reachable.
                await using (var reachability = new NpgsqlCommand(
                    "SELECT pg_catalog.pg_has_role(@elevated, 'SET')", overprivileged))
                {
                    reachability.Parameters.AddWithValue("elevated", elevatedRole);
                    Assert.True(Assert.IsType<bool>(await reachability.ExecuteScalarAsync()));
                }

                var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
                    PostgresRuntimePrivilegePreflight.VerifyAsync(
                        overprivileged, login, CancellationToken.None));
                Assert.Null(ex.InnerException);
                Assert.DoesNotContain(login, ex.ToString());
                Assert.DoesNotContain(elevatedRole, ex.ToString());
                Assert.DoesNotContain(bridgeRole, ex.ToString());
                Assert.DoesNotContain(password, ex.ToString());
            }
        }
        finally
        {
            // Run on expected RED and unexpected failure. Revoke individual
            // test-only role grants before dropping role hierarchy.
            if (elevatedGranted)
                await OwnerExecuteAsync(
                    $"REVOKE {elevatedRole} FROM {(useIntermediateGroup ? bridgeRole : login)}");
            if (bridgeGranted)
                await OwnerExecuteAsync($"REVOKE {bridgeRole} FROM {login}");
            if (runtimeGroupGranted)
                await OwnerExecuteAsync($"REVOKE temporalmark_runtime_group FROM {login}");
            if (bridgeCreated)
                await OwnerExecuteAsync($"DROP ROLE {bridgeRole}");
            if (elevatedCreated)
                await OwnerExecuteAsync($"DROP ROLE {elevatedRole}");
            if (loginCreated)
                await OwnerExecuteAsync($"DROP ROLE {login}");
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
    // #148 / ADR 0113: additional reviewer-only SECURITY DEFINER routines
    // from immutable V010 and V012. Neither is ever invoked in these tests.
    [InlineData("reject_enrollment(uuid,text,text,text,text,text,char(64),char(64),text)")]
    [InlineData("issue_reviewer_decision_challenge(uuid,text,text,text,text,text,char(64),text,text)")]
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
