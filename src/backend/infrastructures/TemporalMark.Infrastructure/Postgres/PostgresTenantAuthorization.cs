using Npgsql;
using TemporalMark.Business.Tenancy;

namespace TemporalMark.Infrastructure.Postgres;

public sealed class PostgresTenantAuthorization(NpgsqlDataSource database) : ITenantAuthorization
{
    public async Task<bool> IsActiveAdminAsync(Guid organizationId, string subjectId, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty || string.IsNullOrWhiteSpace(subjectId))
            return false;
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT EXISTS (
                SELECT 1
                FROM organization_memberships m
                INNER JOIN organizations o ON o.id = m.organization_id
                WHERE o.is_active = TRUE
                  AND m.organization_id = @org
                  AND m.subject_id = @subject
                  AND m.role = 'tenant_admin'
                  AND m.is_active = TRUE
            )
            """, connection);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("subject", subjectId);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken) ?? false);
    }
}
