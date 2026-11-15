using Npgsql;
using TemporalMark.Business.Tenancy;

namespace TemporalMark.Infrastructure.Postgres;

/// <summary>
/// Separately configured registrar-only SQL LOGIN (NOT migration owner, API,
/// provisioner or approver). The NOLOGIN group has no seeded membership.
/// This adapter NEVER accepts a signing key, JWT, approval, WebAuthn response
/// or organization request. V015 revokes this LOGIN's inherited ability to
/// invoke V013: an approved cryptographic ceremony is still absent and this
/// method MUST fail closed for all ordinary registrar executors.
/// </summary>
public sealed class PostgresReviewerRegistrationIntentStore : IReviewerRegistrationIntentStore
{
    private readonly NpgsqlDataSource database;
    private readonly string login;

    public PostgresReviewerRegistrationIntentStore(
        NpgsqlDataSource registrarDatabase, string expectedSqlLogin)
    {
        database = registrarDatabase ?? throw new ArgumentNullException(nameof(registrarDatabase));
        if (string.IsNullOrEmpty(expectedSqlLogin) ||
            expectedSqlLogin.Length > 63 ||
            !(expectedSqlLogin.StartsWith("temporalmark_registrar_", StringComparison.Ordinal) ||
              expectedSqlLogin.StartsWith("ci_registrar_", StringComparison.Ordinal)) ||
            expectedSqlLogin.Any(c => !(c is >= 'a' and <= 'z' or
                >= '0' and <= '9' or '_')) ||
            expectedSqlLogin is "temporalmark_registrar_group" or
                "temporalmark_registrar_owner")
            throw new ArgumentException(
                "An independently configured, dedicated restricted registrar LOGIN is required.",
                nameof(expectedSqlLogin));
        login = expectedSqlLogin;
    }

    public async Task<RegistrarIntentStorageResult> IssueAsync(
        PreflightedRegistrarRegistrationIntent request, CancellationToken ct)
    {
        if (request is null)
            throw new UnauthorizedAccessException("No verified two-person registrar scope.");
        await using var connection = await database.OpenConnectionAsync(ct);

        // Check actual DB principal and the absence of broad table rights on
        // THIS opened connection. Never trust a connection-string Username
        // alone, a session SET ROLE, or a superuser/owner connection.
        await using (var guard = new NpgsqlCommand("""
            SELECT session_user::text, current_user::text,
                   r.rolsuper, r.rolcreaterole, r.rolcreatedb,
                   pg_catalog.pg_has_role(current_user,
                     'temporalmark_credential_registrar_group', 'MEMBER'),
                   pg_catalog.has_table_privilege(current_user,
                     'public.reviewer_registration_intents','SELECT,INSERT,UPDATE,DELETE'),
                   pg_catalog.has_table_privilege(current_user,
                     'public.reviewer_registration_rp_policies','SELECT,INSERT,UPDATE,DELETE'),
                   pg_catalog.pg_has_role(current_user, 'temporalmark_approver_group', 'MEMBER'),
                   pg_catalog.pg_has_role(current_user, 'temporalmark_provisioner_group', 'MEMBER'),
                   pg_catalog.pg_has_role(current_user, 'temporalmark_runtime_group', 'MEMBER'),
                   pg_catalog.has_function_privilege(current_user,
                     'public.issue_reviewer_registration_intent(text,text,text,text,text)',
                     'EXECUTE')
            FROM pg_catalog.pg_roles AS r
            WHERE r.rolname = session_user
            """, connection))
        await using (var guardReader = await guard.ExecuteReaderAsync(ct))
        {
            if (!await guardReader.ReadAsync(ct) ||
                guardReader.GetString(0) != login ||
                guardReader.GetString(1) != login ||
                guardReader.GetBoolean(2) || guardReader.GetBoolean(3) ||
                guardReader.GetBoolean(4) || !guardReader.GetBoolean(5) ||
                guardReader.GetBoolean(6) || guardReader.GetBoolean(7) ||
                guardReader.GetBoolean(8) || guardReader.GetBoolean(9) ||
                guardReader.GetBoolean(10) || guardReader.GetBoolean(11) ||
                await guardReader.ReadAsync(ct))
                throw new UnauthorizedAccessException(
                    "Invalid registrar SQL executor or unreviewed legacy issuance regrant.");
        }

        // Deliberately NO SQL issuance call. The old V013 entry point
        // accepted unsigned arbitrary SQL subjects; even if someone REGRANTS
        // its EXECUTE privilege this application MUST remain fail closed.
        // Future FIDO2-verified, one-time signed release requires a NEW
        // versioned SQL function and separately audited .NET call path.
        throw new UnauthorizedAccessException(
            "V015 registrar issuance is suspended pending an independently signed and consumed registration ceremony.");
    }
}
