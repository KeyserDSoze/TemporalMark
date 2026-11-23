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
        HasAllowedOriginalDerLength(record.ResponseDer) &&
        IsRequiredOriginalTextAdmissible(record.HashAlgorithmOid) &&
        IsRequiredOriginalTextAdmissible(record.DigestBase64) &&
        IsRequiredOriginalTextAdmissible(record.PolicyOid) &&
        IsRequiredOriginalTextAdmissible(record.ProviderId) &&
        (record.EvidenceReference is null ||
         IsOriginalTextWithinBytes(
             record.EvidenceReference, TimestampRegistryService.EvidenceReferenceLimitBytes));

    private static bool HasAllowedOriginalDerLength(byte[]? originalDer) =>
        originalDer is { Length: > 0 } &&
        originalDer.Length <= TimestampRegistryService.ExportReceiptDerLimitBytes;

    private static bool IsRequiredOriginalTextAdmissible(string? originalText) =>
        !string.IsNullOrWhiteSpace(originalText) &&
        IsOriginalTextWithinBytes(
            originalText, TimestampRegistryService.MetadataTextFieldLimitBytes);

    private static bool IsOriginalTextWithinBytes(string originalText, int limitBytes) =>
        originalText.Length <= limitBytes &&
        Encoding.UTF8.GetByteCount(originalText) <= limitBytes;
}
