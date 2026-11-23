using Npgsql;
using TemporalMark.Business.Stamping;
using TemporalMark.Domain.Stamping;

namespace TemporalMark.Infrastructure.Postgres;

/// <summary>
/// Pilot PostgreSQL adapter. Production must additionally persist evidence to an audited WORM store.
/// </summary>
public sealed class PostgresTimestampWriter(NpgsqlDataSource database) : ITimestampWriter
{
    public async Task AppendAsync(TimestampRecord record, CancellationToken cancellationToken)
    {
        // #177 / ADR 0135: direct internal/alternate callers must not
        // persist a new receipt the pilot read/download/export routes deny.
        // Fail closed before DER SHA hashing, acquiring a database connection
        // or transmitting any original text/DER to PostgreSQL.
        if (!TimestampRegistryWriteBudget.IsNewRegistryRecordAdmissible(record))
            throw new InvalidOperationException(
                "Stored receipt exceeds pilot registry write limits.");
        record.Validate();
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO timestamp_registry
                (id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
                 policy_oid, provider_id, token_sha256_hex, validation_state,
                 response_der, evidence_reference)
            VALUES (@id, @org, @issued, @algorithm, @digest, @policy, @provider, @sha, @state, @der, @evidence)
            """, connection);
        command.Parameters.AddWithValue("id", record.Id);
        command.Parameters.AddWithValue("org", record.OrganizationId);
        command.Parameters.AddWithValue("issued", record.IssuedUtc.UtcDateTime);
        command.Parameters.AddWithValue("algorithm", record.HashAlgorithmOid);
        command.Parameters.AddWithValue("digest", record.DigestBase64);
        command.Parameters.AddWithValue("policy", record.PolicyOid);
        command.Parameters.AddWithValue("provider", record.ProviderId);
        command.Parameters.AddWithValue("sha", record.TokenSha256Hex);
        command.Parameters.AddWithValue("state", (short)record.ValidationState);
        command.Parameters.AddWithValue("der", record.ResponseDer);
        command.Parameters.AddWithValue("evidence", (object?)record.EvidenceReference ?? DBNull.Value);
        await command.ExecuteNonQueryAsync(cancellationToken);
    }
}
