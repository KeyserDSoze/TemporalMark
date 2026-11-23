using System.Text;
using TemporalMark.Business.Registry;
using TemporalMark.Domain.Stamping;

namespace TemporalMark.Business.Stamping;

/// <summary>
/// #177 / ADR 0135: app-owned NEW receipts must remain consumable by the
/// existing unqualified pilot registry read/download/export budgets.
/// Not a DER/CMS validator, issuer trust policy, WORM store or qualification.
/// Does not mutate or truncate original evidence or reissue any TSA request.
/// </summary>
public static class TimestampRegistryWriteBudget
{
    /// <summary>
    /// A provider result is checked after exactly one upstream request and
    /// BEFORE hashing or appending DER. Issuance itself constructs the fixed
    /// SHA-256 algorithm OID and canonical 44-character imprint text.
    /// </summary>
    public static bool IsProviderReceiptAdmissible(ProviderTimestamp? receipt) =>
        receipt is not null &&
        HasAllowedOriginalDerLength(receipt.ResponseDer) &&
        IsRequiredOriginalTextAdmissible(receipt.PolicyOid) &&
        IsRequiredOriginalTextAdmissible(receipt.ProviderId);

    /// <summary>
    /// Direct writers also enforce the four persisted NOT NULL original
    /// metadata text fields and nullable original evidence reference.
    /// Do not hash oversized DER and do not open the SQL connection first.
    /// Historic owner-modified rows remain covered by independent read gates.
    /// </summary>
    public static bool IsNewRegistryRecordAdmissible(TimestampRecord? record) =>
        record is not null &&
        // #178 / ADR 0136: the only currently authorized NEW pilot state
        // is Unverified. Future qualification/incident states still exist
        // in Domain and historic V001, but have no approved append workflow.
        // Deny direct writer calls before DER SHA or any SQL connection.
        record.ValidationState == TimestampValidationState.Unverified &&
        HasAllowedOriginalDerLength(record.ResponseDer) &&
        IsRequiredOriginalTextAdmissible(record.HashAlgorithmOid) &&
        IsRequiredOriginalTextAdmissible(record.DigestBase64) &&
        // #179 / ADR 0137: the SHA-256-only pilot searches by this exact
        // OID + canonical 32-byte imprint. Direct appends must not bypass
        // the issuer's separate canonical Base64 ingress policy.
        HasCanonicalPilotSha256Imprint(record.HashAlgorithmOid, record.DigestBase64) &&
        IsRequiredOriginalTextAdmissible(record.PolicyOid) &&
        IsRequiredOriginalTextAdmissible(record.ProviderId) &&
        (record.EvidenceReference is null ||
         IsOriginalTextWithinBytes(
             record.EvidenceReference, TimestampRegistryService.EvidenceReferenceLimitBytes));

    // A 32-byte SHA-256 document imprint is exactly 44 characters in
    // standard padded Base64. Check this BEFORE decoding to avoid large
    // allocations, and round-trip ordinally to deny whitespace aliases and
    // RFC4648 nonzero unused pad bits tolerated by Convert.FromBase64String.
    // This verifies *metadata syntax*, NOT the signer or RFC3161 CMS content.
    // #180 / ADR 0138: shared with the authorized read-side pilot gate;
    // pure metadata syntax only, not qualified timestamp validation.
    internal static bool HasCanonicalPilotSha256Imprint(
        string? hashAlgorithmOid, string? digestBase64)
    {
        if (!string.Equals(hashAlgorithmOid, "2.16.840.1.101.3.4.2.1",
                StringComparison.Ordinal) || digestBase64 is not { Length: 44 })
            return false;

        try
        {
            var decoded = Convert.FromBase64String(digestBase64);
            return decoded.Length == 32 &&
                   string.Equals(Convert.ToBase64String(decoded), digestBase64,
                       StringComparison.Ordinal);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool HasAllowedOriginalDerLength(byte[]? originalDer) =>
        originalDer is { Length: > 0 } &&
        originalDer.Length <= TimestampRegistryService.ExportReceiptDerLimitBytes;

    // #182 / ADR 0140: Python's strict v1 ZIP checker treats U+001C–U+001F
    // as whitespace under str.strip(), unlike .NET char.IsWhiteSpace.
    // Require *some* genuine nonblank source character under BOTH
    // definitions; retain original bytes, including embedded C0 characters.
    // This is not identifier syntax, signer trust or a qualification check.
    internal static bool HasPilotOfflineNonblankText(string? originalText)
    {
        if (originalText is null)
            return false;

        foreach (var character in originalText)
        {
            if (!char.IsWhiteSpace(character) &&
                (character < '\u001c' || character > '\u001f'))
                return true;
        }
        return false;
    }

    private static bool IsRequiredOriginalTextAdmissible(string? originalText) =>
        originalText is not null &&
        HasPilotOfflineNonblankText(originalText) &&
        IsOriginalTextWithinBytes(
            originalText, TimestampRegistryService.MetadataTextFieldLimitBytes);

    private static bool IsOriginalTextWithinBytes(string originalText, int limitBytes) =>
        originalText.Length <= limitBytes &&
        Encoding.UTF8.GetByteCount(originalText) <= limitBytes;
}
