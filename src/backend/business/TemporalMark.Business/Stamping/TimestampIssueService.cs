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
        // A 32-byte SHA-256 hash has precisely 44 characters in standard
        // padded Base64 (one '='). Refuse oversized/alias text BEFORE any
        // decoder allocation; this is an API profile, not RFC3161 policy.
        if (digestBase64 is null || digestBase64.Length != 44)
            throw new ArgumentException("A canonical SHA-256 Base64 digest is required.", nameof(digestBase64));

        byte[] digest;
        try { digest = Convert.FromBase64String(digestBase64); }
        catch (FormatException)
        {
            throw new ArgumentException("A canonical SHA-256 Base64 digest is required.", nameof(digestBase64));
        }

        // .NET's decoder permits ignorable whitespace and is not a
        // canonical spelling check. Re-encode and compare ordinally to
        // reject nonzero unused pad bits and alternate representations.
        if (digest.Length != 32 ||
            !string.Equals(Convert.ToBase64String(digest), digestBase64, StringComparison.Ordinal))
            throw new ArgumentException("A canonical SHA-256 Base64 digest is required.", nameof(digestBase64));

        var receipt = await provider.RequestAsync(digest, cancellationToken);
        // #177 / ADR 0135: the source bytes and operator-owned identity
        // must fit pilot registry read budgets BEFORE hashing DER or invoking
        // any writer. A buggy alternate TSA adapter must never create a 201
        // receipt that the authenticated owner cannot later download.
        // Preserve fixed sanitized 502 provider-response semantics; do not
        // log or reflect the original untrusted provider field.
        if (!TimestampRegistryWriteBudget.IsProviderReceiptAdmissible(receipt))
            throw new TimestampProviderResponseException(
                "External TSA response exceeds pilot registry persistence limits.");
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
