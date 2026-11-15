using System.Security.Cryptography;
using TemporalMark.Domain.Stamping;

namespace TemporalMark.Business.Stamping;

/// <summary>
/// Requests a timestamp for a SHA-256 digest, stores the original response,
/// but NEVER claims a qualified or legally validated timestamp automatically.
/// </summary>
public sealed class TimestampIssueService(ITimestampProvider provider, ITimestampWriter writer)
{
    public async Task<TimestampRecord> IssueAsync(
        Guid organizationId,
        string digestBase64,
        CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("An authorized organization is required.", nameof(organizationId));
        if (string.IsNullOrWhiteSpace(digestBase64))
            throw new ArgumentException("The SHA-256 digest is required.", nameof(digestBase64));

        byte[] digest;
        try { digest = Convert.FromBase64String(digestBase64); }
        catch (FormatException) { throw new ArgumentException("Digest must be Base64.", nameof(digestBase64)); }

        if (digest.Length != 32)
            throw new ArgumentException("Only SHA-256 (32 bytes) is accepted.", nameof(digestBase64));

        var receipt = await provider.RequestAsync(digest, cancellationToken);
        var record = new TimestampRecord(
            Guid.NewGuid(), organizationId, receipt.GeneratedAtUtc.ToUniversalTime(),
            "2.16.840.1.101.3.4.2.1", Convert.ToBase64String(digest),
            receipt.PolicyOid, receipt.ProviderId,
            Convert.ToHexString(SHA256.HashData(receipt.ResponseDer)),
            TimestampValidationState.Unverified, receipt.ResponseDer, null);
        record.Validate();
        await writer.AppendAsync(record, cancellationToken);
        return record;
    }
}
