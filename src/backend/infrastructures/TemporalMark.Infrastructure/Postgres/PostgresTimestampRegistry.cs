using Npgsql;
using TemporalMark.Business.Registry;
using TemporalMark.Domain.Stamping;

namespace TemporalMark.Infrastructure.Postgres;

/// <summary>Every SQL query constrains the organization ID at the database boundary.</summary>
public sealed class PostgresTimestampRegistry(NpgsqlDataSource database) : ITimestampRegistry
{
    public async Task<TimestampRecord?> FindByIdAsync(
        Guid organizationId, Guid recordId, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
                   policy_oid, provider_id, token_sha256_hex, validation_state,
                   response_der, evidence_reference
              FROM timestamp_registry
             WHERE organization_id = @org AND id = @id
            """, connection);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("id", recordId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        return await reader.ReadAsync(cancellationToken) ? MapRecord(reader) : null;
    }

    private static TimestampRecord MapRecord(NpgsqlDataReader reader) =>
        new(
                reader.GetGuid(0),
                reader.GetGuid(1),
                new DateTimeOffset(reader.GetDateTime(2), TimeSpan.Zero),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetString(6),
                reader.GetString(7),
                (TimestampValidationState)reader.GetInt16(8),
                reader.GetFieldValue<byte[]>(9),
                reader.IsDBNull(10) ? null : reader.GetString(10)
        );

    public async Task<IReadOnlyList<TimestampRecord>> SearchByDigestAsync(
        Guid organizationId, UtcPeriod period, string digestBase64,
        int offset, int maxResults, CancellationToken cancellationToken)
    {
        // Always constrain BOTH server-selected organization and period.
        // Digest matching is exact canonical Base64 for SHA-256 document
        // imprint, not a search on the token's own token_sha256_hex.
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
                   policy_oid, provider_id, token_sha256_hex, validation_state,
                   response_der, evidence_reference
              FROM timestamp_registry
             WHERE organization_id = @org
               AND issued_utc >= @start AND issued_utc < @end
               AND hash_algorithm_oid = @algorithm AND digest_base64 = @digest
             ORDER BY issued_utc, id
             LIMIT @limit OFFSET @offset
            """, connection);
        SetCommonParameters(command, organizationId, period);
        command.Parameters.AddWithValue("algorithm", "2.16.840.1.101.3.4.2.1");
        command.Parameters.AddWithValue("digest", digestBase64);
        command.Parameters.AddWithValue("limit", maxResults);
        command.Parameters.AddWithValue("offset", offset);
        var records = new List<TimestampRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            records.Add(MapRecord(reader));
        return records;
    }

    public async Task<long> CountAsync(Guid organizationId, UtcPeriod period, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT count(*) FROM timestamp_registry WHERE organization_id = @org AND issued_utc >= @start AND issued_utc < @end",
            connection);
        SetCommonParameters(command, organizationId, period);
        return (long)(await command.ExecuteScalarAsync(cancellationToken) ?? 0L);
    }

    public async Task<IReadOnlyList<RegistryDayCount>> CountByUtcDayAsync(
        Guid organizationId, UtcPeriod period, CancellationToken cancellationToken)
    {
        // PostgreSQL session timezone must NOT change a tenant's UTC-day
        // buckets. Convert timestamptz to UTC wall-clock before casting date;
        // retain both tenant and half-open UTC timestamp range predicates.
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT (issued_utc AT TIME ZONE 'UTC')::date AS utc_day,
                   count(*)::bigint AS day_count
              FROM timestamp_registry
             WHERE organization_id = @org AND issued_utc >= @start AND issued_utc < @end
             GROUP BY utc_day
             ORDER BY utc_day
            """, connection);
        SetCommonParameters(command, organizationId, period);
        var groups = new List<RegistryDayCount>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
            groups.Add(new RegistryDayCount(reader.GetFieldValue<DateOnly>(0), reader.GetInt64(1)));
        return groups;
    }

    public Task<IReadOnlyList<TimestampRecord>> PageAsync(
        Guid organizationId, UtcPeriod period, int offset, int limit, CancellationToken cancellationToken) =>
        ReadAsync(organizationId, period, offset, limit, cancellationToken);

    public Task<IReadOnlyList<TimestampRecord>> ForExportAsync(
        Guid organizationId, UtcPeriod period, int maxResults, CancellationToken cancellationToken) =>
        ReadAsync(organizationId, period, 0, maxResults, cancellationToken);

    private async Task<IReadOnlyList<TimestampRecord>> ReadAsync(
        Guid organizationId, UtcPeriod period, int offset, int limit, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
                   policy_oid, provider_id, token_sha256_hex, validation_state,
                   response_der, evidence_reference
              FROM timestamp_registry
             WHERE organization_id = @org AND issued_utc >= @start AND issued_utc < @end
             ORDER BY issued_utc, id
             LIMIT @limit OFFSET @offset
            """, connection);
        SetCommonParameters(command, organizationId, period);
        command.Parameters.AddWithValue("limit", limit);
        command.Parameters.AddWithValue("offset", offset);
        var records = new List<TimestampRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            records.Add(MapRecord(reader));
        }
        return records;
    }

    private static void SetCommonParameters(NpgsqlCommand command, Guid organizationId, UtcPeriod period)
    {
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("start", period.FromUtc.UtcDateTime);
        command.Parameters.AddWithValue("end", period.ToUtcExclusive.UtcDateTime);
    }
}
