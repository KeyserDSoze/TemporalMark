using System.Security.Cryptography.Pkcs;
using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Restrictive, UNQUALIFIED RFC3161 pilot TSTInfo extension interoperability
/// gate; neither a general RFC3161 requirement nor proof of QTSP trust.
/// </summary>
public static class ExternalRfc3161TstInfoExtensionPolicy
{
    private const string RejectionMessage =
        "The signed RFC 3161 TSTInfo contains unsupported timestamp extensions.";

    /// <summary>
    /// Accept only after independently verifying CMS signature, message
    /// imprint, nonce, signer, signed policy/genTime, PKIX and issuer CRLs.
    /// No extension OID/bytes are logged, whitelisted or interpreted.
    /// </summary>
    public static void ValidateVerifiedTokenInfo(Rfc3161TimestampTokenInfo? verifiedTokenInfo)
    {
        // The .NET 10 TSTInfo decoder parses [1] IMPLICIT Extensions
        // but does not establish semantics for arbitrary extension OIDs.
        // This intentionally strict pilot accepts no TSTInfo extension.
        if (verifiedTokenInfo is null || verifiedTokenInfo.HasExtensions)
            throw new TimestampProviderResponseException(RejectionMessage);
    }
}
