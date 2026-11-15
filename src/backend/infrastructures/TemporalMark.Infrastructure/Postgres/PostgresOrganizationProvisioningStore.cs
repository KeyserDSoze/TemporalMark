using Npgsql;
using TemporalMark.Business.Tenancy;

namespace TemporalMark.Infrastructure.Postgres;

/// <summary>Dedicated privileged connection. NEVER reuse the normal API DB identity.</summary>
public sealed class PostgresOrganizationProvisioningStore(NpgsqlDataSource privilegedDatabase)
    : IOrganizationProvisioningStore
{
    public async Task CreateAsync(VerifiedOrganizationEnrollment entry, CancellationToken ct)
    {
        await using var connection = await privilegedDatabase.OpenConnectionAsync(ct);
        await using var command = new NpgsqlCommand("""
            SELECT public.bootstrap_verified_organization(
                @organization,@name,@admin,@issuer,@operator,
                @operatorProof::char(64),@adminProof::char(64))
            """, connection);
        command.Parameters.AddWithValue("organization", entry.OrganizationId);
        command.Parameters.AddWithValue("name", entry.OrganizationName);
        command.Parameters.AddWithValue("admin", entry.FirstAdminSubject);
        command.Parameters.AddWithValue("issuer", entry.IdentityIssuer);
        command.Parameters.AddWithValue("operator", entry.ProvisionerSubject);
        command.Parameters.AddWithValue("operatorProof", entry.OperatorProofHashHex);
        command.Parameters.AddWithValue("adminProof", entry.AdminProofHashHex);
        var created = (Guid?)await command.ExecuteScalarAsync(ct);
        if (created != entry.OrganizationId)
            throw new InvalidOperationException("Provisioning result mismatch: organization was not created.");
    }
}
