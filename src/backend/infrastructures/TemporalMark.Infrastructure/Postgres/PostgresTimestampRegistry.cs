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
            SELECT t.id, t.organization_id, t.issued_utc,
                   CASE WHEN admission.allowed THEN t.hash_algorithm_oid ELSE NULL::text END AS hash_algorithm_oid,
                   CASE WHEN admission.allowed THEN t.digest_base64 ELSE NULL::text END AS digest_base64,
                   CASE WHEN admission.allowed THEN t.policy_oid ELSE NULL::text END AS policy_oid,
                   CASE WHEN admission.allowed THEN t.provider_id ELSE NULL::text END AS provider_id,
                   t.token_sha256_hex, t.validation_state,
                   CASE WHEN admission.allowed THEN t.response_der ELSE NULL::bytea END AS response_der,
                   CASE WHEN admission.allowed THEN t.evidence_reference ELSE NULL::text END AS evidence_reference
              FROM public.timestamp_registry AS t
             CROSS JOIN LATERAL (
                SELECT (
                    octet_length(t.response_der) <= @max_receipt_bytes
                    AND COALESCE(octet_length(t.evidence_reference), 0) <= @max_ref_bytes
                    AND GREATEST(octet_length(t.hash_algorithm_oid),
                                 octet_length(t.digest_base64),
                                 octet_length(t.policy_oid),
                                 octet_length(t.provider_id)) <= @max_metadata_field_bytes
                ) AS allowed
             ) AS admission
             WHERE t.organization_id = @org AND t.id = @id
            """, connection);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("id", recordId);
        command.Parameters.AddWithValue(
            "max_receipt_bytes", TimestampRegistryService.ExportReceiptDerLimitBytes);
        command.Parameters.AddWithValue(
            "max_ref_bytes", TimestampRegistryService.EvidenceReferenceLimitBytes);
        command.Parameters.AddWithValue(
            "max_metadata_field_bytes", TimestampRegistryService.MetadataTextFieldLimitBytes);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        // A truly missing/foreign record has no row -> 404. An authorized
        // oversized legacy row has a row but no projected bytea -> 409.
        // Check before MapRecord calls Npgsql GetFieldValue<byte[]>(9).
        if (!await reader.ReadAsync(cancellationToken))
            return null;
        if (reader.IsDBNull(3) || reader.IsDBNull(9))
            throw new ReceiptTooLargeException();
        return MapRecord(reader);
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

    /// <summary>
    /// Page/search only: one SQL statement/snapshot first chooses ID and
    /// logical DER length, then hides ALL raw bytea in the SQL projection if
    /// any selected row or the aggregate exceeds the shared pilot budget.
    /// The caller's independent SHA-256/tenant/status checks remain intact.
    /// </summary>
    public Task<IReadOnlyList<TimestampRecord>> SearchByDigestAsync(
        Guid organizationId, UtcPeriod period, string digestBase64,
        int offset, int maxResults, CancellationToken cancellationToken) =>
        ReadBoundedMetadataAsync(
            organizationId, period, offset, maxResults, digestBase64, cancellationToken);

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
        ReadBoundedMetadataAsync(
            organizationId, period, offset, limit, digestBase64: null, cancellationToken);

    public Task<IReadOnlyList<TimestampRecord>> ForExportAsync(
        Guid organizationId, UtcPeriod period, int maxResults, CancellationToken cancellationToken) =>
        ReadBoundedExportAsync(organizationId, period, maxResults, cancellationToken);

    // Both queries deliberately contain only id + logical bytea length in
    // MATERIALIZED chosen, with the original ORDER BY / LIMIT / OFFSET. No
    // bytea is selected into either CTE. The final CASE controls whether
    // the PostgreSQL wire result contains any DER at all; the JOIN reads
    // the same row versions as chosen because this is ONE SELECT snapshot.
    // PostgreSQL 17: WITH materialization and CASE lazy row projection.
    // Query execution/TOAST metadata and accepted <=64MiB batches still
    // consume resources; this is not a global concurrency memory limit.
    private const string BoundedPageSql = """
        WITH chosen AS MATERIALIZED (
            SELECT id, octet_length(response_der)::bigint AS der_bytes,
                   COALESCE(octet_length(evidence_reference), 0)::bigint AS ref_bytes,
                   GREATEST(octet_length(hash_algorithm_oid), octet_length(digest_base64),
                            octet_length(policy_oid), octet_length(provider_id))::bigint
                       AS max_metadata_field_bytes,
                   (octet_length(hash_algorithm_oid)::bigint +
                    octet_length(digest_base64)::bigint +
                    octet_length(policy_oid)::bigint +
                    octet_length(provider_id)::bigint) AS metadata_bytes
              FROM public.timestamp_registry
             WHERE organization_id = @org AND issued_utc >= @start AND issued_utc < @end
             ORDER BY issued_utc, id
             LIMIT @limit OFFSET @offset
        ),
        guarded AS MATERIALIZED (
            SELECT id,
                   bool_and(der_bytes BETWEEN 1 AND @max_receipt_bytes) OVER () AS all_receipts_ok,
                   sum(der_bytes) OVER () AS batch_bytes,
                   bool_and(ref_bytes <= @max_ref_bytes) OVER () AS refs_ok,
                   sum(ref_bytes) OVER () AS ref_batch_bytes,
                   bool_and(max_metadata_field_bytes <= @max_metadata_field_bytes) OVER ()
                       AS metadata_fields_ok,
                   sum(metadata_bytes) OVER () AS metadata_batch_bytes
              FROM chosen
        )
        SELECT t.id, t.organization_id, t.issued_utc,
               CASE WHEN admission.allowed THEN t.hash_algorithm_oid ELSE NULL::text END AS hash_algorithm_oid,
               CASE WHEN admission.allowed THEN t.digest_base64 ELSE NULL::text END AS digest_base64,
               CASE WHEN admission.allowed THEN t.policy_oid ELSE NULL::text END AS policy_oid,
               CASE WHEN admission.allowed THEN t.provider_id ELSE NULL::text END AS provider_id,
               t.token_sha256_hex, t.validation_state,
               CASE WHEN admission.allowed THEN t.response_der ELSE NULL::bytea END AS response_der,
               CASE WHEN admission.allowed THEN t.evidence_reference ELSE NULL::text END AS evidence_reference
          FROM guarded AS g
          JOIN public.timestamp_registry AS t
            ON t.id = g.id AND t.organization_id = @org
         CROSS JOIN LATERAL (
             SELECT (g.all_receipts_ok
                        AND g.batch_bytes <= @max_batch_bytes
                        AND g.refs_ok AND g.ref_batch_bytes <= @max_ref_batch_bytes
                        AND g.metadata_fields_ok
                        AND g.metadata_batch_bytes <= @max_metadata_batch_bytes) AS allowed
         ) AS admission
         ORDER BY t.issued_utc, t.id
        """;

    private const string BoundedSearchSql = """
        WITH chosen AS MATERIALIZED (
            SELECT id, octet_length(response_der)::bigint AS der_bytes,
                   COALESCE(octet_length(evidence_reference), 0)::bigint AS ref_bytes,
                   GREATEST(octet_length(hash_algorithm_oid), octet_length(digest_base64),
                            octet_length(policy_oid), octet_length(provider_id))::bigint
                       AS max_metadata_field_bytes,
                   (octet_length(hash_algorithm_oid)::bigint +
                    octet_length(digest_base64)::bigint +
                    octet_length(policy_oid)::bigint +
                    octet_length(provider_id)::bigint) AS metadata_bytes
              FROM public.timestamp_registry
             WHERE organization_id = @org AND issued_utc >= @start AND issued_utc < @end
               AND hash_algorithm_oid = @algorithm AND digest_base64 = @digest
             ORDER BY issued_utc, id
             LIMIT @limit OFFSET @offset
        ),
        guarded AS MATERIALIZED (
            SELECT id,
                   bool_and(der_bytes BETWEEN 1 AND @max_receipt_bytes) OVER () AS all_receipts_ok,
                   sum(der_bytes) OVER () AS batch_bytes,
                   bool_and(ref_bytes <= @max_ref_bytes) OVER () AS refs_ok,
                   sum(ref_bytes) OVER () AS ref_batch_bytes,
                   bool_and(max_metadata_field_bytes <= @max_metadata_field_bytes) OVER ()
                       AS metadata_fields_ok,
                   sum(metadata_bytes) OVER () AS metadata_batch_bytes
              FROM chosen
        )
        SELECT t.id, t.organization_id, t.issued_utc,
               CASE WHEN admission.allowed THEN t.hash_algorithm_oid ELSE NULL::text END AS hash_algorithm_oid,
               CASE WHEN admission.allowed THEN t.digest_base64 ELSE NULL::text END AS digest_base64,
               CASE WHEN admission.allowed THEN t.policy_oid ELSE NULL::text END AS policy_oid,
               CASE WHEN admission.allowed THEN t.provider_id ELSE NULL::text END AS provider_id,
               t.token_sha256_hex, t.validation_state,
               CASE WHEN admission.allowed THEN t.response_der ELSE NULL::bytea END AS response_der,
               CASE WHEN admission.allowed THEN t.evidence_reference ELSE NULL::text END AS evidence_reference
          FROM guarded AS g
          JOIN public.timestamp_registry AS t
            ON t.id = g.id AND t.organization_id = @org
         CROSS JOIN LATERAL (
             SELECT (g.all_receipts_ok
                        AND g.batch_bytes <= @max_batch_bytes
                        AND g.refs_ok AND g.ref_batch_bytes <= @max_ref_batch_bytes
                        AND g.metadata_fields_ok
                        AND g.metadata_batch_bytes <= @max_metadata_batch_bytes) AS allowed
         ) AS admission
         ORDER BY t.issued_utc, t.id
        """;

    private async Task<IReadOnlyList<TimestampRecord>> ReadBoundedMetadataAsync(
        Guid organizationId, UtcPeriod period, int offset, int limit,
        string? digestBase64, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            digestBase64 is null ? BoundedPageSql : BoundedSearchSql,
            connection);
        SetCommonParameters(command, organizationId, period);
        command.Parameters.AddWithValue("limit", limit);
        command.Parameters.AddWithValue("offset", offset);
        command.Parameters.AddWithValue(
            "max_receipt_bytes", TimestampRegistryService.ExportReceiptDerLimitBytes);
        command.Parameters.AddWithValue(
            "max_batch_bytes", TimestampRegistryService.ExportTotalDerLimitBytes);
        command.Parameters.AddWithValue(
            "max_ref_bytes", TimestampRegistryService.EvidenceReferenceLimitBytes);
        command.Parameters.AddWithValue(
            "max_ref_batch_bytes", TimestampRegistryService.EvidenceReferenceBatchLimitBytes);
        command.Parameters.AddWithValue(
            "max_metadata_field_bytes", TimestampRegistryService.MetadataTextFieldLimitBytes);
        command.Parameters.AddWithValue(
            "max_metadata_batch_bytes", TimestampRegistryService.MetadataTextBatchLimitBytes);
        if (digestBase64 is not null)
        {
            command.Parameters.AddWithValue("algorithm", "2.16.840.1.101.3.4.2.1");
            command.Parameters.AddWithValue("digest", digestBase64);
        }

        var records = new List<TimestampRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            // SQL returns NULL::bytea for EVERY row of an over-budget batch,
            // even if only the later search lookahead receipt is invalid.
            // Reject before Npgsql.GetFieldValue<byte[]> can materialize DER.
            if (reader.IsDBNull(3) || reader.IsDBNull(9))
                throw new InvalidOperationException(
                    "Registry evidence exceeded PostgreSQL pre-materialization byte limits.");
            records.Add(MapRecord(reader));
        }
        return records;
    }

    // #173 / ADR 0131: keep export's HTTP 413 contract, rather than
    // reusing page/search's generic InvalidOperationException. One PG17
    // statement/snapshot selects ONLY IDs and logical bytea lengths in
    // the materialized CTE; a whole-batch row/size gate controls the
    // eventual PostgreSQL wire projection of raw retained DER.
    //
    // A failed 1MiB / 64MiB / 10k-record budget yields NULL::bytea
    // for EVERY selected row, and ExportTooLargeException is thrown
    // before Npgsql GetFieldValue<byte[]> materializes any raw receipt.
    // This does not bound internal TOAST I/O or accepted concurrent loads.
    private const string BoundedExportSql = """
        WITH chosen AS MATERIALIZED (
            SELECT id, octet_length(response_der)::bigint AS der_bytes,
                   COALESCE(octet_length(evidence_reference), 0)::bigint AS ref_bytes,
                   GREATEST(octet_length(hash_algorithm_oid), octet_length(digest_base64),
                            octet_length(policy_oid), octet_length(provider_id))::bigint
                       AS max_metadata_field_bytes,
                   (octet_length(hash_algorithm_oid)::bigint +
                    octet_length(digest_base64)::bigint +
                    octet_length(policy_oid)::bigint +
                    octet_length(provider_id)::bigint) AS metadata_bytes
              FROM public.timestamp_registry
             WHERE organization_id = @org
               AND issued_utc >= @start AND issued_utc < @end
             ORDER BY issued_utc, id
             LIMIT @limit
        ),
        guarded AS MATERIALIZED (
            SELECT id,
                   bool_and(der_bytes BETWEEN 1 AND @max_receipt_bytes) OVER () AS all_receipts_ok,
                   sum(der_bytes) OVER () AS batch_bytes,
                   bool_and(ref_bytes <= @max_ref_bytes) OVER () AS refs_ok,
                   sum(ref_bytes) OVER () AS ref_batch_bytes,
                   bool_and(max_metadata_field_bytes <= @max_metadata_field_bytes) OVER ()
                       AS metadata_fields_ok,
                   sum(metadata_bytes) OVER () AS metadata_batch_bytes,
                   count(*) OVER () AS record_count
              FROM chosen
        )
        SELECT t.id, t.organization_id, t.issued_utc,
               CASE WHEN admission.allowed THEN t.hash_algorithm_oid ELSE NULL::text END AS hash_algorithm_oid,
               CASE WHEN admission.allowed THEN t.digest_base64 ELSE NULL::text END AS digest_base64,
               CASE WHEN admission.allowed THEN t.policy_oid ELSE NULL::text END AS policy_oid,
               CASE WHEN admission.allowed THEN t.provider_id ELSE NULL::text END AS provider_id,
               t.token_sha256_hex, t.validation_state,
               CASE WHEN admission.allowed THEN t.response_der ELSE NULL::bytea END AS response_der,
               CASE WHEN admission.allowed THEN t.evidence_reference ELSE NULL::text END AS evidence_reference
          FROM guarded AS g
          JOIN public.timestamp_registry AS t
            ON t.id = g.id AND t.organization_id = @org
         CROSS JOIN LATERAL (
             SELECT (g.all_receipts_ok
                        AND g.batch_bytes <= @max_batch_bytes
                        AND g.refs_ok AND g.ref_batch_bytes <= @max_ref_batch_bytes
                        AND g.metadata_fields_ok
                        AND g.metadata_batch_bytes <= @max_metadata_batch_bytes
                        AND g.record_count <= @max_records) AS allowed
         ) AS admission
         ORDER BY t.issued_utc, t.id
        """;

    private async Task<IReadOnlyList<TimestampRecord>> ReadBoundedExportAsync(
        Guid organizationId, UtcPeriod period, int maxResults,
        CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(BoundedExportSql, connection);
        SetCommonParameters(command, organizationId, period);
        command.Parameters.AddWithValue("limit", maxResults);
        command.Parameters.AddWithValue(
            "max_receipt_bytes", TimestampRegistryService.ExportReceiptDerLimitBytes);
        command.Parameters.AddWithValue(
            "max_batch_bytes", TimestampRegistryService.ExportTotalDerLimitBytes);
        command.Parameters.AddWithValue(
            "max_ref_bytes", TimestampRegistryService.EvidenceReferenceLimitBytes);
        command.Parameters.AddWithValue(
            "max_ref_batch_bytes", TimestampRegistryService.EvidenceReferenceBatchLimitBytes);
        command.Parameters.AddWithValue(
            "max_metadata_field_bytes", TimestampRegistryService.MetadataTextFieldLimitBytes);
        command.Parameters.AddWithValue(
            "max_metadata_batch_bytes", TimestampRegistryService.MetadataTextBatchLimitBytes);
        command.Parameters.AddWithValue("max_records", TimestampRegistryService.ExportLimit);

        var records = new List<TimestampRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            // A later over-budget row invalidates the *entire* batch,
            // including all earlier rows. Do not expose any partial result
            // or change ExportZipAsync's original HTTP 413 error mapping.
            if (reader.IsDBNull(3) || reader.IsDBNull(9))
                throw new ExportTooLargeException();
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
