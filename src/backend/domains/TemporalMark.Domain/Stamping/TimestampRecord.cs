using TemporalMark.Domain;

namespace TemporalMark.Domain.Stamping;

public enum TimestampValidationState
{
    Unverified = 0,
    VerifiedNonQualified = 1,
    VerifiedQualifiedExternal = 2,
    VerifiedQualifiedOwn = 3,
    AffectedByIncident = 4
}

/// <summary>
/// One externally evidenced timestamp. The raw RFC 3161 DER response is preserved;
/// documents themselves are never stored here.
/// </summary>
public sealed record TimestampRecord(
    Guid Id,
    Guid OrganizationId,
    DateTimeOffset IssuedUtc,
    string HashAlgorithmOid,
    string DigestBase64,
    string PolicyOid,
    string ProviderId,
    string TokenSha256Hex,
    TimestampValidationState ValidationState,
    byte[] ResponseDer,
    string? EvidenceReference)
{
    public void Validate()
    {
        if (Id == Guid.Empty || OrganizationId == Guid.Empty)
            throw new DomainRuleException("Record and organization IDs must be nonempty.");
        if (IssuedUtc.Offset != TimeSpan.Zero)
            throw new DomainRuleException("Issuance timestamp must be UTC.");
        if (string.IsNullOrWhiteSpace(ProviderId) || string.IsNullOrWhiteSpace(HashAlgorithmOid))
            throw new DomainRuleException("The provider and imprint algorithm are mandatory.");
        if (ResponseDer.Length == 0)
            throw new DomainRuleException("The actual RFC 3161 response must be retained.");
        if (!Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(ResponseDer))
                .Equals(TokenSha256Hex, StringComparison.OrdinalIgnoreCase))
            throw new DomainRuleException("The stored token digest does not match its DER bytes.");
    }
}
