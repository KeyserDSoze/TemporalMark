namespace TemporalMark.Business.Tenancy;

/// <summary>
/// Fail-closed, deployment-pinned WebAuthn relying-party scope for a FUTURE
/// maintained assertion verifier. Matching these public strings is NOT
/// authentication, signature verification, key enrollment or reviewer consent.
/// Never build this policy from request headers, browser input or a JWT claim.
/// </summary>
public sealed class ReviewerWebAuthnRelyingPartyPolicy
{
    public string RelyingPartyId { get; }
    public string TrustedOrigin { get; }

    /// <summary>
    /// A deliberately conservative profile: an exact HTTPS origin and a DNS
    /// RP ID equal to its host. The WebAuthn standard allows broader RP-ID
    /// suffix relationships, but those require public-suffix and origin policy
    /// review that this pilot does NOT perform.
    /// </summary>
    public ReviewerWebAuthnRelyingPartyPolicy(string relyingPartyId, string trustedOrigin)
    {
        if (string.IsNullOrEmpty(trustedOrigin) ||
            trustedOrigin.Any(c => c > 0x7f) ||
            !Uri.TryCreate(trustedOrigin, UriKind.Absolute, out var uri) ||
            !string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) ||
            uri.HostNameType != UriHostNameType.Dns ||
            uri.IsLoopback ||
            uri.Port is < 1 or > 65535 ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            !string.Equals(trustedOrigin, uri.GetLeftPart(UriPartial.Authority),
                StringComparison.Ordinal) ||
            !IsStrictAsciiDnsName(uri.IdnHost))
            throw new ArgumentException(
                "A canonical, absolute HTTPS origin on a non-loopback DNS host is required.",
                nameof(trustedOrigin));

        if (!string.Equals(relyingPartyId, uri.IdnHost, StringComparison.Ordinal))
            throw new ArgumentException(
                "The RP ID must be exactly the server-approved HTTPS origin host.",
                nameof(relyingPartyId));

        TrustedOrigin = trustedOrigin;
        RelyingPartyId = relyingPartyId;
    }

    /// <summary>
    /// Compare already-extracted assertion values against the server policy.
    /// The future verifier MUST independently parse and cryptographically
    /// validate clientDataJSON/authenticatorData, rpIdHash, signed challenge,
    /// UV, registered credential and counter BEFORE authorizing a decision.
    /// This predicate on its own NEVER authorizes any enrollment or decision.
    /// </summary>
    public bool MatchesDeclaredScope(string? assertionOrigin, string? assertionRpId) =>
        string.Equals(TrustedOrigin, assertionOrigin, StringComparison.Ordinal) &&
        string.Equals(RelyingPartyId, assertionRpId, StringComparison.Ordinal);

    private static bool IsStrictAsciiDnsName(string host)
    {
        if (string.IsNullOrEmpty(host) || host.Length > 253)
            return false;

        // No wildcard, IP literal, single-label host, trailing dot, IDN Unicode
        // confusable, or URI authority syntax. ASCII A-labels can be pinned
        // explicitly, but deployment must approve the real DNS domain.
        var labels = host.Split('.');
        if (labels.Length < 2 || labels[^1].All(c => c is >= '0' and <= '9'))
            return false;

        foreach (var label in labels)
        {
            if (label.Length is < 1 or > 63 ||
                !IsAsciiLowerAlphanumeric(label[0]) ||
                !IsAsciiLowerAlphanumeric(label[^1]) ||
                label.Any(c => !IsAsciiLowerAlphanumeric(c) && c != '-'))
                return false;
        }

        return true;
    }

    private static bool IsAsciiLowerAlphanumeric(char value) =>
        value is >= 'a' and <= 'z' or >= '0' and <= '9';
}
