using Npgsql;
using TemporalMark.Business.Tenancy;

namespace TemporalMark.Infrastructure.Postgres;

/// <summary>One narrow role per action; the caller supplies only its assigned DB login.</summary>
public sealed class PostgresOrganizationApprovalStore(NpgsqlDataSource database) : IOrganizationApprovalStore
{
    public Task<Guid> RequestAsync(VerifiedOrganizationEnrollment request, CancellationToken ct) =>
        ExecuteEnrollmentAsync("request_enrollment", request, ct);

    public Task<Guid> CompleteAsync(VerifiedOrganizationEnrollment completion, CancellationToken ct) =>
        ExecuteEnrollmentAsync("complete_enrollment", completion, ct);

    private async Task<Guid> ExecuteEnrollmentAsync(
        string routine, VerifiedOrganizationEnrollment entry, CancellationToken ct)
    {
        // Fixed routine names only, no SQL fragments from user-supplied data.
        if (routine != "request_enrollment" && routine != "complete_enrollment")
            throw new InvalidOperationException("Unknown restricted enrollment operation.");
        await using var conn = await database.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand($"""
            SELECT public.{routine}(@id,@name,@issuer,@operator,@admin,
                                    @operatorHash::char(64),@adminHash::char(64))
            """, conn);
        cmd.Parameters.AddWithValue("id", entry.OrganizationId);
        cmd.Parameters.AddWithValue("name", entry.OrganizationName);
        cmd.Parameters.AddWithValue("issuer", entry.IdentityIssuer);
        cmd.Parameters.AddWithValue("operator", entry.ProvisionerSubject);
        cmd.Parameters.AddWithValue("admin", entry.FirstAdminSubject);
        cmd.Parameters.AddWithValue("operatorHash", entry.OperatorProofHashHex);
        cmd.Parameters.AddWithValue("adminHash", entry.AdminProofHashHex);
        return AssertGuid(await cmd.ExecuteScalarAsync(ct));
    }

    public async Task<Guid> ApproveAsync(VerifiedOrganizationApproval approval, CancellationToken ct)
    {
        await using var conn = await database.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("""
            SELECT public.approve_enrollment(@id,@name,@issuer,@operator,@admin,
                    @approver,@proof::char(64),@kind,@context,@authTime)
            """, conn);
        cmd.Parameters.AddWithValue("id", approval.OrganizationId);
        cmd.Parameters.AddWithValue("name", approval.ExpectedOrganizationName);
        cmd.Parameters.AddWithValue("issuer", approval.IdentityIssuer);
        cmd.Parameters.AddWithValue("operator", approval.ExpectedOperatorSubject);
        cmd.Parameters.AddWithValue("admin", approval.ExpectedAdminSubject);
        cmd.Parameters.AddWithValue("approver", approval.ApproverSubject);
        cmd.Parameters.AddWithValue("proof", approval.ApprovalProofHashHex);
        cmd.Parameters.AddWithValue("kind", approval.AuthenticationEvidence.Kind);
        var context = cmd.Parameters.Add("context", NpgsqlTypes.NpgsqlDbType.Text);
        context.Value = (object?)approval.AuthenticationEvidence.Context ?? DBNull.Value;
        var authTime = cmd.Parameters.Add("authTime", NpgsqlTypes.NpgsqlDbType.Bigint);
        authTime.Value = (object?)approval.AuthenticationEvidence.AuthenticationTimeUnix ?? DBNull.Value;
        return AssertGuid(await cmd.ExecuteScalarAsync(ct));
    }

    private static Guid AssertGuid(object? result) =>
        result is Guid id && id != Guid.Empty
            ? id : throw new InvalidOperationException("Enrollment routine did not return a valid UUID.");
}
