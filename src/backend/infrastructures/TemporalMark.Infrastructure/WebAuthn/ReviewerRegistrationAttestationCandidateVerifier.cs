using System.Security.Cryptography;
using Fido2NetLib;
using Fido2NetLib.Objects;
using TemporalMark.Business.Tenancy;

namespace TemporalMark.Infrastructure.WebAuthn;

/// <summary>
/// Not a trusted registration transcript or an approved signer. These input
/// values MUST originate from an independently authenticated server-side
/// immutable ceremony record, never from HTTP headers or client-supplied
/// JSON. At present no such repository/service is wired to this verifier.
/// </summary>
public sealed record ReviewerRegistrationAttestationCeremony(
    string IdentityIssuer, string ReviewerSubject, string RegistrarSubject,
    byte[] ExpectedChallenge, byte[] ExpectedUserHandle,
    DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc);

/// <summary>
/// Non-authorizing result only. It deliberately contains NO public key,
/// credential secret, approved reviewer, trusted attestation or SQL action.
/// The hashes cannot be substituted for attestation verification or an
/// independently approved credential registry.
/// </summary>
public sealed record ReviewerAttestationReviewCandidate(
    string ReviewStatus, string IdentityIssuer,
    string ReviewerSubject, string RegistrarSubject, string RelyingPartyId,
    string CredentialIdSha256, string PublicKeySha256,
    string AttestationType, string AttestationFormat, Guid AuthenticatorAaguid,
    uint SignCount, bool IsBackupEligible, bool IsBackedUp);

/// <summary>
/// Isolated adapter around the maintained Fido2 library (currently 4.3.3).
/// Invoking it cannot create ACTIVE credentials, issue SQL nonces, approve
/// organizations or bypass V015/V016. It produces only quarantined metadata.
/// The caller MUST supply a trusted globally unique-credential callback and
/// an original server-owned challenge/options record; neither currently
/// has a production DB-backed implementation, so this is NOT yet a complete
/// WebAuthn registration ceremony or a claim of hardware provenance.
/// </summary>
public sealed class ReviewerRegistrationAttestationCandidateVerifier
{
    private readonly IFido2 verifier;
    private readonly ReviewerWebAuthnRelyingPartyPolicy relyingParty;
    private readonly TimeProvider clock;

    public ReviewerRegistrationAttestationCandidateVerifier(
        IFido2 maintainedFido2Verifier,
        ReviewerWebAuthnRelyingPartyPolicy approvedRelyingParty,
        TimeProvider? timeProvider = null)
    {
        verifier = maintainedFido2Verifier ?? throw new ArgumentNullException(nameof(maintainedFido2Verifier));
        relyingParty = approvedRelyingParty ?? throw new ArgumentNullException(nameof(approvedRelyingParty));
        clock = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Constructs the real library with EXACT approved HTTPS origin and DNS
    /// RP ID; no localhost/related-origin/conditional-create exception.
    /// No Metadata Service is configured: no attestation may be marked trusted.
    /// </summary>
    public static ReviewerRegistrationAttestationCandidateVerifier Create(
        ReviewerWebAuthnRelyingPartyPolicy approvedRelyingParty)
    {
        ArgumentNullException.ThrowIfNull(approvedRelyingParty);
        var configuration = new Fido2Configuration
        {
            RPID = approvedRelyingParty.RelyingPartyId,
            RPName = "TemporalMark Reviewer Registration",
            Origins = new HashSet<string>(StringComparer.Ordinal)
            {
                approvedRelyingParty.TrustedOrigin
            },
            ChallengeSize = 48
        };
        configuration.Validate();
        return new ReviewerRegistrationAttestationCandidateVerifier(
            new Fido2(configuration), approvedRelyingParty);
    }

    /// <remarks>
    /// A fake IFido2 in unit tests only verifies fail-closed orchestration.
    /// A real IFido2 validates authenticator data/CBOR/clientData/signatures;
    /// basic/attca/anonca are *candidates*, NOT trusted device attestation
    /// without separately approved MDS/certificate anchors and human review.
    /// </remarks>
    public async Task<ReviewerAttestationReviewCandidate> VerifyCandidateAsync(
        ReviewerRegistrationAttestationCeremony? ceremony,
        CredentialCreateOptions? originalServerOptions,
        AuthenticatorAttestationRawResponse? browserResponse,
        IsCredentialIdUniqueToUserAsyncDelegate? globallyUniqueCredentialId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var now = clock.GetUtcNow();
        if (ceremony is null || originalServerOptions is null ||
            browserResponse is null || globallyUniqueCredentialId is null ||
            !ValidSubject(ceremony.ReviewerSubject) ||
            !ValidSubject(ceremony.RegistrarSubject) ||
            ceremony.ReviewerSubject == ceremony.RegistrarSubject ||
            !ValidIssuer(ceremony.IdentityIssuer) ||
            ceremony.IssuedUtc > now.AddSeconds(5) ||
            ceremony.IssuedUtc < now.AddMinutes(-2) ||
            ceremony.ExpiresUtc <= now ||
            ceremony.ExpiresUtc <= ceremony.IssuedUtc ||
            ceremony.ExpiresUtc > ceremony.IssuedUtc.AddMinutes(2) ||
            ceremony.ExpectedChallenge is not { Length: 48 } ||
            ceremony.ExpectedUserHandle is not { Length: 32 } ||
            originalServerOptions.Challenge is not { Length: 48 } ||
            !CryptographicOperations.FixedTimeEquals(
                ceremony.ExpectedChallenge, originalServerOptions.Challenge) ||
            originalServerOptions.Rp is null ||
            originalServerOptions.Rp.Id != relyingParty.RelyingPartyId ||
            originalServerOptions.User?.Id is not { Length: 32 } ||
            !CryptographicOperations.FixedTimeEquals(
                ceremony.ExpectedUserHandle, originalServerOptions.User.Id) ||
            originalServerOptions.Attestation is not (
                AttestationConveyancePreference.Direct or
                AttestationConveyancePreference.Enterprise) ||
            originalServerOptions.AuthenticatorSelection?.UserVerification !=
                UserVerificationRequirement.Required ||
            originalServerOptions.PubKeyCredParams is null ||
            originalServerOptions.PubKeyCredParams.Count == 0 ||
            browserResponse.Type != PublicKeyCredentialType.PublicKey ||
            browserResponse.RawId is not { Length: >= 16 and <= 1024 } ||
            browserResponse.Id != ToBase64Url(browserResponse.RawId) ||
            browserResponse.Response is null ||
            browserResponse.Response.AttestationObject is not { Length: >= 4 and <= 131072 } ||
            browserResponse.Response.ClientDataJson is not { Length: >= 2 and <= 16384 })
            throw new UnauthorizedAccessException(
                "Untrusted or expired reviewer attestation ceremony cannot be verified.");

        RegisteredPublicKeyCredential verified;
        try
        {
            verified = await verifier.MakeNewCredentialAsync(new MakeNewCredentialParams
            {
                AttestationResponse = browserResponse,
                OriginalOptions = originalServerOptions,
                IsCredentialIdUniqueToUserCallback = globallyUniqueCredentialId,
                // Explicitly retain Optional: never use Conditional to waive
                // authenticator user presence for a privileged key ceremony.
                Mediation = CredentialMediationRequirement.Optional
            }, cancellationToken);
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            throw new UnauthorizedAccessException(
                "Maintained Fido2 library rejected the registration attestation.", error);
        }

        if (verified is null ||
            verified.AttestationType is not ("basic" or "attca" or "anonca") ||
            string.IsNullOrWhiteSpace(verified.AttestationFormat) ||
            verified.RpId != relyingParty.RelyingPartyId ||
            verified.Id is not { Length: >= 16 and <= 1024 } ||
            !CryptographicOperations.FixedTimeEquals(verified.Id, browserResponse.RawId) ||
            verified.User?.Id is not { Length: 32 } ||
            !CryptographicOperations.FixedTimeEquals(
                verified.User.Id, ceremony.ExpectedUserHandle) ||
            verified.PublicKey is not { Length: >= 32 and <= 4096 })
            throw new UnauthorizedAccessException(
                "Attestation result is unapproved or does not match the original scope.");

        // Deliberately no public key material is returned. A new, separately
        // approved FIDO metadata/trust chain, device governance and atomic
        // SQL ceremony is required before this material could ever become
        // a registered/revocable WebAuthn credential.
        return new ReviewerAttestationReviewCandidate(
            "UNAPPROVED", ceremony.IdentityIssuer,
            ceremony.ReviewerSubject, ceremony.RegistrarSubject,
            relyingParty.RelyingPartyId,
            Convert.ToHexString(SHA256.HashData(verified.Id)),
            Convert.ToHexString(SHA256.HashData(verified.PublicKey)),
            verified.AttestationType, verified.AttestationFormat,
            verified.AaGuid, verified.SignCount, verified.IsBackupEligible,
            verified.IsBackedUp);
    }

    private static bool ValidSubject(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 255 &&
        value == value.Trim() && !value.Any(char.IsControl);

    private static bool ValidIssuer(string? issuer) =>
        !string.IsNullOrWhiteSpace(issuer) &&
        issuer == issuer.Trim() &&
        Uri.TryCreate(issuer, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps &&
        uri.UserInfo.Length == 0 &&
        uri.Fragment.Length == 0 &&
        uri.Query.Length == 0 &&
        uri.HostNameType == UriHostNameType.Dns &&
        !uri.IsLoopback;

    private static string ToBase64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
