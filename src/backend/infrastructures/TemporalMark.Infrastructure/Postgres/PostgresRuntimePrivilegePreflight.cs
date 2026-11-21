using System.Data;
using System.Text.RegularExpressions;
using Npgsql;

namespace TemporalMark.Infrastructure.Postgres;

/// <summary>
/// #133 / ADR 0099 + #141 / ADR 0106: read-only privilege preflight
/// on an ALREADY OPEN PostgreSQL runtime connection. Mandatory before HTTP
/// listening only in explicit #134 ContainerAppsEntraCandidate API mode;
/// never selected by default Password mode, privileged CLIs or Terraform.
/// PostgreSQL must independently authenticate the session first.
/// </summary>
public static class PostgresRuntimePrivilegePreflight
{
    private const string Failure = "PostgreSQL runtime privilege preflight denied";

    // Static SQL only: inspect current session, effective role attributes,
    // transitive membership including SET ROLE capability, and actual object
    // ACLs. Not a substitute for SQL grants/ownership review or RLS.
    // Names here are known immutable schema policy and never user input.
    private const string Sql = """
        SELECT
            current_user = @expected_login
            AND session_user = @expected_login
            AND EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles r
                WHERE r.rolname = current_user
                  AND r.rolcanlogin
                  AND NOT r.rolsuper
                  AND NOT r.rolcreatedb
                  AND NOT r.rolcreaterole
                  AND NOT r.rolreplication
                  AND NOT r.rolbypassrls
            )
            AND pg_catalog.pg_has_role('temporalmark_runtime_group', 'MEMBER')
            AND NOT pg_catalog.pg_has_role('temporalmark_provisioner_group', 'MEMBER')
            AND NOT pg_catalog.pg_has_role('temporalmark_approver_group', 'MEMBER')
            AND NOT pg_catalog.pg_has_role('temporalmark_credential_registrar_group', 'MEMBER')
            AND NOT EXISTS (
                SELECT 1 FROM pg_catalog.pg_roles elevated
                WHERE elevated.rolname IN (
                    'pg_monitor',
                    'pg_read_all_data',
                    'pg_write_all_data',
                    'pg_execute_server_program',
                    'pg_read_server_files',
                    'pg_write_server_files',
                    'azure_pg_admin'
                )
                  AND pg_catalog.pg_has_role(elevated.oid, 'MEMBER')
            )
            AND NOT pg_catalog.has_database_privilege(current_database(), 'CREATE')
            AND pg_catalog.has_schema_privilege('public', 'USAGE')
            AND NOT pg_catalog.has_schema_privilege('public', 'CREATE')
            AND pg_catalog.has_table_privilege('public.organizations', 'SELECT')
            AND pg_catalog.has_table_privilege('public.organization_memberships', 'SELECT')
            AND pg_catalog.has_table_privilege('public.timestamp_registry', 'INSERT')
            AND pg_catalog.has_table_privilege('public.tenant_audit_events', 'INSERT')
            -- #141 / ADR 0106: these are append-only pilot evidence
            -- surfaces. Prevent a mis-granted runtime SQL principal from
            -- passing pre-listen with destructive rights. UPDATE/REFERENCES
            -- can be granted per column, so table-only ACL checks miss them.
            AND NOT pg_catalog.has_any_column_privilege(
                'public.timestamp_registry', 'UPDATE')
            AND NOT pg_catalog.has_any_column_privilege(
                'public.timestamp_registry', 'REFERENCES')
            AND NOT pg_catalog.has_table_privilege('public.timestamp_registry', 'DELETE')
            AND NOT pg_catalog.has_table_privilege('public.timestamp_registry', 'TRUNCATE')
            AND NOT pg_catalog.has_table_privilege('public.timestamp_registry', 'TRIGGER')
            AND NOT pg_catalog.has_any_column_privilege(
                'public.tenant_audit_events', 'UPDATE')
            AND NOT pg_catalog.has_any_column_privilege(
                'public.tenant_audit_events', 'REFERENCES')
            AND NOT pg_catalog.has_table_privilege('public.tenant_audit_events', 'DELETE')
            AND NOT pg_catalog.has_table_privilege('public.tenant_audit_events', 'TRUNCATE')
            AND NOT pg_catalog.has_table_privilege('public.tenant_audit_events', 'TRIGGER')
            AND NOT pg_catalog.has_table_privilege('public.organizations', 'INSERT')
            AND NOT pg_catalog.has_table_privilege('public.organizations', 'UPDATE')
            AND NOT pg_catalog.has_table_privilege('public.organizations', 'DELETE')
            AND NOT pg_catalog.has_table_privilege('public.organizations', 'TRUNCATE')
            AND NOT pg_catalog.has_table_privilege('public.organization_memberships', 'INSERT')
            AND NOT pg_catalog.has_table_privilege('public.organization_memberships', 'UPDATE')
            AND NOT pg_catalog.has_table_privilege('public.organization_memberships', 'DELETE')
            AND NOT pg_catalog.has_table_privilege('public.organization_memberships', 'TRUNCATE')
            AND NOT pg_catalog.has_function_privilege(
                'public.bootstrap_organization(uuid,text,text)', 'EXECUTE')
            AND NOT pg_catalog.has_function_privilege(
                'public.bootstrap_verified_organization(uuid,text,text,text,text,char(64),char(64))',
                'EXECUTE')
        """;

    /// <summary>
    /// Checks the effective privileges of the real connected PostgreSQL
    /// session only. The expected login comes from independently approved
    /// operator configuration, never an HTTP client or OIDC subject.
    /// No network connection is initiated and no SQL write is issued.
    /// </summary>
    public static async Task VerifyAsync(
        NpgsqlConnection connection,
        string expectedRuntimeLogin,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(connection);

        if (string.IsNullOrWhiteSpace(expectedRuntimeLogin) ||
            !Regex.IsMatch(expectedRuntimeLogin,
                @"\A[A-Za-z_][A-Za-z0-9_-]{1,62}\z",
                RegexOptions.CultureInvariant))
            throw new ArgumentException("A canonical approved PostgreSQL runtime login is required",
                nameof(expectedRuntimeLogin));

        cancellationToken.ThrowIfCancellationRequested();

        // Must not call Open/OpenAsync: the caller must have authenticated the
        // intended session already, e.g. the Entra-only #130 data source.
        if (connection.State != ConnectionState.Open)
            throw new InvalidOperationException(Failure);

        try
        {
            await using var command = new NpgsqlCommand(Sql, connection);
            command.Parameters.AddWithValue("expected_login", expectedRuntimeLogin);
            var result = await command.ExecuteScalarAsync(cancellationToken);
            if (result is not true)
                throw new InvalidOperationException(Failure);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // Never retain an Npgsql/SQL exception as InnerException: server
            // messages may contain names, internal SQL, hosts or credential
            // values. A failed catalog/ACL check fails closed.
            throw new InvalidOperationException(Failure);
        }
    }
}
