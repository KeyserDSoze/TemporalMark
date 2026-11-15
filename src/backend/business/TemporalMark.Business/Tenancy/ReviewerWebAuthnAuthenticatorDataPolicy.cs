using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace TemporalMark.Business.Tenancy;

/// <summary>
/// Purely structural, UNTRUSTED WebAuthn assertion authenticator-data metadata.
/// The 32-byte RP hash, flags and counter are attacker-controlled until a
/// separately enrolled reviewer credential verifies the full WebAuthn signature.
/// Do not persist or rely on these values for authorization or replay detection.
/// </summary>
public sealed record ReviewerAuthenticatorDataPreflight(
    uint SignCount, bool BackupEligible, bool BackedUp);

/// <summary>
/// Strict first-profile WebAuthn assertion preflight. Passing does NOT mean
/// possession of a key, signed consent, UV performed, challenge consumed,
/// issuer verified or a reviewer decision authorized. There is deliberately
/// no operation here that can approve/reject or update SQL.
/// </summary>
public static class ReviewerWebAuthnAuthenticatorDataPolicy
{
    private const int BasicAssertionLength = 37;
    private const byte MandatoryUpUv = 0x05; // UP=bit0; UV=bit2
    private const byte BackupEligibility = 0x08; // BE=bit3
    private const byte BackupState = 0x10; // BS=bit4
    private const byte ReservedAndUnsupported = 0xE2; // RFU1, RFU2, AT, ED

    /// <summary>
    /// Checks a 37-byte *unsigned/untrusted* basic assertion data structure.
    /// The RP ID comes solely from independently pinned server settings.
    /// AT=1 is prohibited for assertions by the W3C specification; this
    /// initial strict profile also denies ED=1 extensions rather than trying
    /// to parse unsolicited CBOR. A future audited verifier may support them.
    /// </summary>
    public static bool TryReadUntrustedAssertionData(
        byte[]? originalAuthenticatorData,
        ReviewerWebAuthnRelyingPartyPolicy? relyingPartyPolicy,
        out ReviewerAuthenticatorDataPreflight? parsed)
    {
        parsed = null;
        if (originalAuthenticatorData is null ||
            originalAuthenticatorData.Length != BasicAssertionLength ||
            relyingPartyPolicy is null)
            return false;

        // RP ID is a canonical lower-case ASCII DNS host validated by ADR 0017.
        // This is only a precondition. An attacker can forge the unsigned hash.
        var expectedHash = SHA256.HashData(
            Encoding.UTF8.GetBytes(relyingPartyPolicy.RelyingPartyId));
        if (!CryptographicOperations.FixedTimeEquals(
            originalAuthenticatorData.AsSpan(0, 32), expectedHash))
            return false;

        var flags = originalAuthenticatorData[32];
        if ((flags & MandatoryUpUv) != MandatoryUpUv ||
            (flags & ReservedAndUnsupported) != 0)
            return false;

        var backupEligible = (flags & BackupEligibility) != 0;
        var backedUp = (flags & BackupState) != 0;
        if (backedUp && !backupEligible)
            return false;

        // Counter is unsigned, network byte order and may legitimately be
        // zero for authenticators without counters. It is merely parsed here;
        // a future verifier MUST compare it to the registered credential's
        // stored count only AFTER validating the signed assertion and then
        // persist the decision and count atomically with replay protections.
        var count = BinaryPrimitives.ReadUInt32BigEndian(
            originalAuthenticatorData.AsSpan(33, 4));

        parsed = new ReviewerAuthenticatorDataPreflight(
            count, backupEligible, backedUp);
        return true;
    }
}
