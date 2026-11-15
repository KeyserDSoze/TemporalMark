namespace TemporalMark.Business.Stamping;

/// <summary>
/// RFC 3161 provider boundary. Provider configuration is server-owned and allowlisted.
/// Returning a cryptographically parsed TSR does NOT assert legal qualified status.
/// </summary>
public interface ITimestampProvider
{
    Task<ProviderTimestamp> RequestAsync(byte[] sha256Digest, CancellationToken cancellationToken);
}

public sealed record ProviderTimestamp(
    byte[] ResponseDer,
    DateTimeOffset GeneratedAtUtc,
    string PolicyOid,
    string ProviderId);

public sealed class TimestampProviderUnavailableException(string message) : Exception(message);
public sealed class TimestampProviderResponseException(string message) : Exception(message);
