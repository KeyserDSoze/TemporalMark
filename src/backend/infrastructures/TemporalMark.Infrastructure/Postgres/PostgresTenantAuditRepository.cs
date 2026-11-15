using Npgsql;
using NpgsqlTypes;
using TemporalMark.Business.Audit;
using TemporalMark.Domain.Audit;
using TemporalMark.Domain.Stamping;

namespace TemporalMark.Infrastructure.Postgres;

/// <summary>Development/pilot SQL event trail; production requires independent immutable sealing.</summary>
public sealed class PostgresTenantAuditRepository(NpgsqlDataSource database) : ITenantAuditRepository
{
    public async Task AppendAsync(TenantAuditEntry entry, CancellationToken cancellationToken)
    {
        entry.Validate();
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO tenant_audit_events
              (id, organization_id, actor_subject_id, action, occurred_utc, receipt_id, period_from_utc, period_to_utc_exclusive)
            VALUES
              (@id, @org, @actor, @action, @occurred, @receipt, @from, @to)
            """, connection);
        command.Parameters.AddWithValue("id", entry.Id);
        command.Parameters.AddWithValue("org", entry.OrganizationId);
        command.Parameters.AddWithValue("actor", entry.ActorSubjectId);
        command.Parameters.AddWithValue("action", ActionToSql(entry.Action));
        command.Parameters.AddWithValue("occurred", entry.OccurredUtc.UtcDateTime);
        command.Parameters.Add("receipt", NpgsqlDbType.Uuid).Value = (object?)entry.ReceiptId ?? DBNull.Value;
        command.Parameters.Add("from", NpgsqlDbType.TimestampTz).Value =
            entry.PeriodFromUtc is { } from ? from.UtcDateTime : DBNull.Value;
        command.Parameters.Add("to", NpgsqlDbType.TimestampTz).Value =
            entry.PeriodToUtcExclusive is { } to ? to.UtcDateTime : DBNull.Value;
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<TenantAuditEntry>> PageAsync(
        Guid organizationId, UtcPeriod period, int offset, int limit, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT id, organization_id, actor_subject_id, action, occurred_utc,
                   receipt_id, period_from_utc, period_to_utc_exclusive
              FROM tenant_audit_events
             WHERE organization_id = @org AND occurred_utc >= @from AND occurred_utc < @to
             ORDER BY occurred_utc DESC, id DESC
             LIMIT @limit OFFSET @offset
            """, connection);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("from", period.FromUtc.UtcDateTime);
        command.Parameters.AddWithValue("to", period.ToUtcExclusive.UtcDateTime);
        command.Parameters.AddWithValue("limit", limit);
        command.Parameters.AddWithValue("offset", offset);
        var result = new List<TenantAuditEntry>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            result.Add(new TenantAuditEntry(
                reader.GetGuid(0), reader.GetGuid(1), reader.GetString(2),
                ActionFromSql(reader.GetString(3)),
                new DateTimeOffset(reader.GetDateTime(4), TimeSpan.Zero),
                reader.IsDBNull(5) ? null : reader.GetGuid(5),
                reader.IsDBNull(6) ? null : new DateTimeOffset(reader.GetDateTime(6), TimeSpan.Zero),
                reader.IsDBNull(7) ? null : new DateTimeOffset(reader.GetDateTime(7), TimeSpan.Zero)));
        }
        return result;
    }

    private static string ActionToSql(TenantAuditAction action) => action switch
    {
        TenantAuditAction.PeriodExportPrepared => "period_export_prepared",
        TenantAuditAction.ReceiptDownloadPrepared => "receipt_download_prepared",
        _ => throw new ArgumentOutOfRangeException(nameof(action))
    };

    private static TenantAuditAction ActionFromSql(string action) => action switch
    {
        "period_export_prepared" => TenantAuditAction.PeriodExportPrepared,
        "receipt_download_prepared" => TenantAuditAction.ReceiptDownloadPrepared,
        _ => throw new InvalidOperationException("Unrecognized persisted audit action.")
    };
}
