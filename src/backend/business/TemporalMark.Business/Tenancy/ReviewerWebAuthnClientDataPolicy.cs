using System.Text;
using System.Text.Json;

namespace TemporalMark.Business.Tenancy;

/// <summary>
/// A bounded, fail-closed check of UNTRUSTED WebAuthn clientDataJSON for a
/// future separately audited assertion verifier. This is not signature,
/// RP-ID-hash, credential, user-verification, or human-consent validation.
///
/// A caller MUST derive the expected 48-byte nonce from the original V012
/// PostgreSQL challenge, never from client input. Never authorize approval or
/// rejection from this predicate: without an independently enrolled key and a
/// verified authenticator signature, all JSON fields remain attacker-controlled.
/// </summary>
public static class ReviewerWebAuthnClientDataPolicy
{
    private const int MaxClientDataJsonBytes = 4096;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    /// <summary>
    /// Checks preconditions for top-level, same-origin "webauthn.get" only.
    /// Unknown JSON keys and key ordering are tolerated, per W3C Level 3.
    /// The future cryptographic verifier MUST hash the ORIGINAL exact JSON
    /// bytes, not serialize this parsed object or use this method as a bypass.
    /// </summary>
    public static bool MatchesUntrustedClientData(
        byte[]? originalClientDataJson,
        byte[]? expectedServerNonce,
        ReviewerWebAuthnRelyingPartyPolicy? relyingPartyPolicy)
    {
        if (originalClientDataJson is null ||
            originalClientDataJson.Length is < 2 or > MaxClientDataJsonBytes ||
            expectedServerNonce is null || expectedServerNonce.Length != 48 ||
            relyingPartyPolicy is null)
            return false;

        try
        {
            // JsonDocument alone is not a strict UTF-8 validation boundary:
            // malformed bytes must never be silently normalized/replaced.
            _ = StrictUtf8.GetCharCount(originalClientDataJson);

            // WebAuthn L3 accepts a UTF-8 BOM, which is stripped for parsing.
            // The original byte[] remains unchanged for future signature hash.
            ReadOnlyMemory<byte> json = originalClientDataJson;
            if (originalClientDataJson.Length >= 3 &&
                originalClientDataJson[0] == 0xEF &&
                originalClientDataJson[1] == 0xBB &&
                originalClientDataJson[2] == 0xBF)
                json = originalClientDataJson.AsMemory(3);

            using var document = JsonDocument.Parse(json,
                new JsonDocumentOptions
                {
                    AllowTrailingCommas = false,
                    CommentHandling = JsonCommentHandling.Disallow,
                    MaxDepth = 8
                });
            if (document.RootElement.ValueKind != JsonValueKind.Object)
                return false;

            string? type = null;
            string? challenge = null;
            string? origin = null;
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var field in document.RootElement.EnumerateObject())
            {
                // Duplicate fields are ambiguous, including \\u-escaped aliases.
                // Unknown unique fields are tolerated per WebAuthn Level 3.
                if (!seen.Add(field.Name))
                    return false;

                switch (field.Name)
                {
                    case "type":
                        if (field.Value.ValueKind != JsonValueKind.String)
                            return false;
                        type = field.Value.GetString();
                        break;
                    case "challenge":
                        if (field.Value.ValueKind != JsonValueKind.String)
                            return false;
                        challenge = field.Value.GetString();
                        break;
                    case "origin":
                        if (field.Value.ValueKind != JsonValueKind.String)
                            return false;
                        origin = field.Value.GetString();
                        break;
                    case "crossOrigin":
                        // This profile does not support embedded/cross-origin
                        // WebAuthn ceremonies or coercion from strings/numbers.
                        if (field.Value.ValueKind != JsonValueKind.False)
                            return false;
                        break;
                    case "topOrigin":
                        // Top-origin delegation requires separate reviewed
                        // policies and is not supported even if crossOrigin=false.
                        return false;
                }
            }

            if (!string.Equals(type, "webauthn.get", StringComparison.Ordinal) ||
                !string.Equals(origin, relyingPartyPolicy.TrustedOrigin,
                    StringComparison.Ordinal))
                return false;

            // The browser's challenge is base64url of the original bytes from
            // the server-issued V012 nonce; require exact unpadded spelling.
            var canonical = Convert.ToBase64String(expectedServerNonce)
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            return string.Equals(challenge, canonical, StringComparison.Ordinal);
        }
        catch (JsonException)
        {
            return false;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
}
