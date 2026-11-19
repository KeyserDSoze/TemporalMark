using Npgsql;
using TemporalMark.Business.Registry;

namespace TemporalMark.Infrastructure.Postgres;

/// <summary>
/// One shared PostgreSQL-primary admission function across API replicas.
/// No local allow-on-error fallback; neither digest nor request body is stored.
/// </summary>
public sealed class PostgresImprintSearchRateRepository(NpgsqlDataSource database)
    : IImprintSearchRateRepository
{
    public async Task<ImprintSearchRateDecision> ConsumeAsync(
        Guid organizationId, string actorSubjectId, CancellationToken cancellationToken)
    {
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT allowed, retry_after_seconds
              FROM public.consume_imprint_search_rate(@org,@actor)
            """, connection);
        command.Parameters.AddWithValue("org", organizationId);
        command.Parameters.AddWithValue("actor", actorSubjectId);

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken) ||
            reader.IsDBNull(0) || reader.IsDBNull(1))
            throw new InvalidOperationException("Shared imprint search gate returned no valid decision.");
        var result = new ImprintSearchRateDecision(reader.GetBoolean(0), reader.GetInt32(1));
        if (await reader.ReadAsync(cancellationToken))
            throw new InvalidOperationException("Shared imprint search gate returned duplicate decisions.");
        return result;
    }
}
