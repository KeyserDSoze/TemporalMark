namespace TemporalMark.Business.Tenancy;

/// <summary>
/// Immutable, operator/change-control approved registrar configuration.
/// Never construct from browser JSON, JWT claims, command arguments or tenant
/// headers. The exact HTTPS origin is deliberately stricter than generic
/// WebAuthn: V013 only accepts https://{RP-ID} on the default TLS port.
/// </summary>
public sealed class RegistrarIntentDeploymentPolicy
{
    public string IdentityIssuer { get; }
    public string RelyingPartyId { get; }
    public string TrustedOrigin { get; }
    public string ApprovedReviewerSubject { get; }

    public RegistrarIntentDeploymentPolicy(
        string identityIssuer, string relyingPartyId,
        string trustedOrigin, string approvedReviewerSubject)
    {
        if (string.IsNullOrWhiteSpace(identityIssuer) ||
            identityIssuer != identityIssuer.Trim() ||
            identityIssuer.EndsWith('/') ||
            !Uri.TryCreate(identityIssuer, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            uri.HostNameType != UriHostNameType.Dns ||
            uri.IsLoopback || uri.UserInfo.Length != 0 ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0)
            throw new ArgumentException("A pinned, non-loopback HTTPS registrar issuer is required.",
                nameof(identityIssuer));

        // Reuse ADR 0017 DNS/HTTPS parser, then enforce V013's more
        // conservative default-port EXACT origin requirement.
        _ = new ReviewerWebAuthnRelyingPartyPolicy(relyingPartyId, trustedOrigin);
        if (trustedOrigin != "https://" + relyingPartyId)
            throw new ArgumentException("V013 permits only the exact default-TLS RP origin.",
                nameof(trustedOrigin));

        if (string.IsNullOrWhiteSpace(approvedReviewerSubject) ||
            approvedReviewerSubject.Length > 255 ||
            approvedReviewerSubject != approvedReviewerSubject.Trim() ||
            approvedReviewerSubject.Any(char.IsControl))
            throw new ArgumentException("An approved exact reviewer identity is required.",
                nameof(approvedReviewerSubject));

        IdentityIssuer = identityIssuer;
        RelyingPartyId = relyingPartyId;
        TrustedOrigin = trustedOrigin;
        ApprovedReviewerSubject = approvedReviewerSubject;
    }
}

/// <summary>
/// Store input may only be created from the concrete dual OIDC identity gate
/// plus deployment-pinned trusted scope. Database credentials remain a separate
/// independently controlled authority and can bypass this application guard.
/// </summary>
public sealed record PreflightedRegistrarRegistrationIntent(
    string IdentityIssuer, string ReviewerSubject, string RegistrarSubject,
    string RelyingPartyId, string TrustedOrigin);

/// <summary>V013 SQL output, NOT a signed or consumed registration ceremony.</summary>
public sealed record RegistrarIntentStorageResult(
    Guid IntentId, string ChallengeHex,
    DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc);

public interface IReviewerRegistrationIntentStore
{
    Task<RegistrarIntentStorageResult> IssueAsync(
        PreflightedRegistrarRegistrationIntent request, CancellationToken ct);
}

/// <summary>
/// Unconsumable, not credential-bound registration intent. This is explicitly
/// NOT approval, authenticator possession, a trusted COSE key or FIDO2 attestation.
/// </summary>
public sealed record IssuedReviewerRegistrationIntent(
    Guid IntentId, string ChallengeHex, DateTimeOffset IssuedUtc,
    DateTimeOffset ExpiresUtc, string IdentityIssuer,
    string ReviewerSubject, string RegistrarSubject,
    string RelyingPartyId, string TrustedOrigin);

/// <summary>
/// Isolated registrar-only intent coordinator; never available from API/PWA.
/// Privileged invokers must independently govern trusted configuration, token
/// file custody and the separate dedicated registrar SQL login.
/// </summary>
public sealed class ReviewerRegistrationIntentWorkflow(
    ReviewerCredentialRegistrarIdentityGate identityGate,
    IReviewerRegistrationIntentStore store,
    RegistrarIntentDeploymentPolicy policy)
{
    private readonly ReviewerCredentialRegistrarIdentityGate gate =
        identityGate ?? throw new ArgumentNullException(nameof(identityGate));
    private readonly IReviewerRegistrationIntentStore storage =
        store ?? throw new ArgumentNullException(nameof(store));
    private readonly RegistrarIntentDeploymentPolicy pinned =
        policy ?? throw new ArgumentNullException(nameof(policy));

    public async Task<IssuedReviewerRegistrationIntent> IssueAsync(
        string? registrarToken, string? reviewerToken, CancellationToken ct)
    {
        // The exact approved reviewer identity is deployment-controlled.
        // For organization-specific reviewer credential issuance, a future
        // operator must also independently fetch and bind the original SQL
        // request subjects (NOT caller-provided fields).
        var verified = await gate.CheckAsync(
            registrarToken, reviewerToken,
            new RegistrarRegistrationIdentityScope(pinned.ApprovedReviewerSubject), ct);
        if (verified.Issuer != pinned.IdentityIssuer ||
            verified.ReviewerSubject != pinned.ApprovedReviewerSubject ||
            verified.RegistrarSubject == verified.ReviewerSubject)
            throw new UnauthorizedAccessException("Registrar OIDC proof is not bound to pinned scope.");

        var request = new PreflightedRegistrarRegistrationIntent(
            verified.Issuer, verified.ReviewerSubject,
            verified.RegistrarSubject, pinned.RelyingPartyId, pinned.TrustedOrigin);
        // Caller never provides SQL text or its own challenge bytes.
        var issued = await storage.IssueAsync(request, ct);
        var now = DateTimeOffset.UtcNow;
        if (issued is null || issued.IntentId == Guid.Empty ||
            issued.ChallengeHex is null || issued.ChallengeHex.Length != 96 ||
            issued.ChallengeHex.Any(ch => !(ch is >= '0' and <= '9' or >= 'A' and <= 'F')) ||
            issued.IssuedUtc < now.AddSeconds(-30) ||
            issued.IssuedUtc > now.AddSeconds(10) ||
            issued.ExpiresUtc <= now ||
            issued.ExpiresUtc <= issued.IssuedUtc ||
            issued.ExpiresUtc > issued.IssuedUtc.AddMinutes(2))
            throw new UnauthorizedAccessException("Database registration intent was not valid or fresh.");

        return new IssuedReviewerRegistrationIntent(
            issued.IntentId, issued.ChallengeHex,
            issued.IssuedUtc, issued.ExpiresUtc,
            request.IdentityIssuer, request.ReviewerSubject,
            request.RegistrarSubject, request.RelyingPartyId, request.TrustedOrigin);
    }
}
