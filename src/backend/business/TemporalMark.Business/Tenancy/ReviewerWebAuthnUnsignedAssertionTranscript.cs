using System.Security.Cryptography;

namespace TemporalMark.Business.Tenancy;

/// <summary>
/// Constructs the WebAuthn signature MESSAGE bytes from the two ORIGINAL,
/// UNTRUSTED byte arrays, only after strict non-authorizing structural checks.
/// This does NOT verify any signature or bind any approved reviewer credential.
/// A successful return never means a human reviewed or signed an enrollment.
/// </summary>
public static class ReviewerWebAuthnUnsignedAssertionTranscript
{
    private const int BasicAuthenticatorBytes = 37;
    private const int Sha256Bytes = 32;

    /// <summary>
    /// For a future separately audited verifier, the *message to verify* is
    /// originalAuthenticatorData || SHA256(originalClientDataJSON).
    /// No normalization or JSON reserialization is permitted.
    ///
    /// Both input policies are ONLY untrusted preconditions. A privileged
    /// verifier still needs a vetted signature library, trusted registered
    /// public key, credential/subject binding, fresh IdP role, exact nonce,
    /// UV, counter policy and atomic challenge consumption. Never turn the
    /// returned bytes into an approval or terminal database decision alone.
    /// </summary>
    public static bool TryBuild(
        byte[]? originalAuthenticatorData,
        byte[]? originalClientDataJson,
        byte[]? expectedServerNonce,
        ReviewerWebAuthnRelyingPartyPolicy? pinnedRelyingParty,
        out byte[]? untrustedSignatureMessage)
    {
        untrustedSignatureMessage = null;

        if (!ReviewerWebAuthnAuthenticatorDataPolicy.TryReadUntrustedAssertionData(
                originalAuthenticatorData, pinnedRelyingParty, out _) ||
            !ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
                originalClientDataJson, expectedServerNonce, pinnedRelyingParty))
            return false;

        // At this point both inputs are non-null and the authenticator-data
        // strict pilot policy has ensured its length is exactly 37 bytes.
        // Output a distinct owned byte[] to avoid input aliasing.
        var authenticatorData = originalAuthenticatorData!;
        var clientData = originalClientDataJson!;
        var signedMessage = new byte[BasicAuthenticatorBytes + Sha256Bytes];
        authenticatorData.CopyTo(signedMessage, 0);
        SHA256.HashData(clientData).CopyTo(signedMessage, BasicAuthenticatorBytes);
        untrustedSignatureMessage = signedMessage;
        return true;
    }
}
