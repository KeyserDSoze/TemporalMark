namespace TemporalMark.Business.Tenancy;

/// <summary>
/// Deployment-owned OIDC policy. No default audience, issuer, role grant or
/// development password-only MFA exception is allowed.
/// </summary>
public sealed record RegistrarIdentityGatePolicy
{
    public string Issuer { get; }
    public string RegistrarAudience { get; }
    public string ReviewerAudience { get; }
    public string RequiredAcr { get; }

    public RegistrarIdentityGatePolicy(
        string issuer, string registrarAudience, string reviewerAudience, string requiredAcr)
    {
        if (!Uri.TryCreate(issuer, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || uri.UserInfo.Length != 0 ||
            uri.Query.Length != 0 || uri.Fragment.Length != 0 ||
            issuer != issuer.TrimEnd('/') ||
            uri.HostNameType != UriHostNameType.Dns ||
            !ValidScope(registrarAudience) || !ValidScope(reviewerAudience) ||
            registrarAudience == reviewerAudience)
            throw new ArgumentException(
                "Explicit pinned HTTPS issuer and distinct OIDC audiences are required.");

        // Use the production freshness policy to reject weak ACR settings at
        // policy construction. Never enable its disposable password grant.
        _ = new ApprovalAuthenticationPolicy(requiredAcr, TimeSpan.FromSeconds(120),
            allowPasswordOnlyDisposableLocalFixture: false);

        Issuer = issuer;
        RegistrarAudience = registrarAudience;
        ReviewerAudience = reviewerAudience;
        RequiredAcr = requiredAcr;
    }

    private static bool ValidScope(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 255 &&
        value == value.Trim() && !value.Any(char.IsWhiteSpace);
}

/// <summary>
/// Expected reviewer subject, and optional ORIGINAL trusted SQL request actors.
/// Inputs are not authenticated by this class; a future privileged caller MUST
/// obtain them from the original reviewed database scope, not browser headers.
/// Both original-request subjects must be provided together or neither.
/// </summary>
public sealed record RegistrarRegistrationIdentityScope(
    string ExpectedReviewerSubject,
    string? OriginalOperatorSubject = null,
    string? OriginalInitialAdminSubject = null);

/// <summary>
/// EPHEMERAL OIDC preflight metadata only. This is NOT a WebAuthn key,
/// registrar approval, credential attestation, MFA certification or SQL grant.
/// </summary>
public sealed record RegistrarIdentityPreflight(
    string Issuer, string RegistrarSubject, string ReviewerSubject,
    long RegistrarAuthenticationTimeUnix, long ReviewerAuthenticationTimeUnix);

/// <summary>
/// Verifies both pinned, distinct user identities against cryptographically
/// validated OIDC claims, fresh live introspection, and independent CURRENT
/// directory user/role state. NO SIGNATURE of a WebAuthn key is verified here.
/// This class has no SQL dependency and must never be used by itself to
/// register/approve a credential or decide an organization enrollment.
/// </summary>
public sealed class ReviewerCredentialRegistrarIdentityGate
{
    private readonly IVerifiedOidcTokenSource verifier;
    private readonly ILiveOidcTokenStatus live;
    private readonly ICurrentOidcAccountDirectory directory;
    private readonly RegistrarIdentityGatePolicy policy;
    private readonly ApprovalAuthenticationPolicy authentication;

    public ReviewerCredentialRegistrarIdentityGate(
        IVerifiedOidcTokenSource verifier,
        ILiveOidcTokenStatus liveStatus,
        ICurrentOidcAccountDirectory currentAccountDirectory,
        RegistrarIdentityGatePolicy policy,
        TimeProvider? timeProvider = null)
    {
        this.verifier = verifier ?? throw new ArgumentNullException(nameof(verifier));
        live = liveStatus ?? throw new ArgumentNullException(nameof(liveStatus));
        directory = currentAccountDirectory ??
            throw new ArgumentNullException(nameof(currentAccountDirectory));
        this.policy = policy ?? throw new ArgumentNullException(nameof(policy));
        authentication = new ApprovalAuthenticationPolicy(
            policy.RequiredAcr, TimeSpan.FromSeconds(120),
            allowPasswordOnlyDisposableLocalFixture: false, timeProvider: timeProvider);
    }

    /// <summary>
    /// All token checks are fresh, never cached; there is NO token replay
    /// consumption or transaction. The future independently governed registrar
    /// issuer MUST enforce one-time operation/nonce semantics after a real
    /// FIDO2 registration flow and approved credential trust policy.
    /// </summary>
    public async Task<RegistrarIdentityPreflight> CheckAsync(
        string? registrarToken, string? reviewerToken,
        RegistrarRegistrationIdentityScope? expectedScope, CancellationToken ct)
    {
        if (!ValidBearer(registrarToken) || !ValidBearer(reviewerToken) ||
            registrarToken == reviewerToken || expectedScope is null ||
            !ValidSubject(expectedScope.ExpectedReviewerSubject) ||
            (expectedScope.OriginalOperatorSubject is null) !=
                (expectedScope.OriginalInitialAdminSubject is null) ||
            (expectedScope.OriginalOperatorSubject is not null &&
                (!ValidSubject(expectedScope.OriginalOperatorSubject) ||
                 !ValidSubject(expectedScope.OriginalInitialAdminSubject))))
            throw new UnauthorizedAccessException("Invalid independent registrar identity scope.");

        // The production OidcAccessTokenVerifier checks pinned issuer, audience,
        // signature algorithm, key, lifetime and freshness before exposing claims.
        var registrar = await verifier.VerifyAsync(registrarToken!, policy.RegistrarAudience, ct);
        var reviewer = await verifier.VerifyAsync(reviewerToken!, policy.ReviewerAudience, ct);
        RequireSigned(registrar, "platform_credential_registrar");
        RequireSigned(reviewer, "platform_approver");
        if (registrar.Subject == reviewer.Subject ||
            reviewer.Subject != expectedScope.ExpectedReviewerSubject)
            throw new UnauthorizedAccessException("The registrar and reviewed identity must be independent.");

        // When binding a pending enrollment, only the ORIGINAL SQL-fetched
        // operator/admin can supply exclusion subjects; caller has to enforce
        // that trust boundary. A credential cannot be trusted from this result.
        if (expectedScope.OriginalOperatorSubject is { } op &&
            expectedScope.OriginalInitialAdminSubject is { } admin &&
            (registrar.Subject == op || registrar.Subject == admin ||
             reviewer.Subject == op || reviewer.Subject == admin))
            throw new UnauthorizedAccessException("Enrollment actors cannot witness their own registration.");

        // A string ACR is not proof the IdP really required MFA, but absence,
        // stale auth_time or a password-only downgrade is always a hard denial.
        var registrarAuth = authentication.Require(registrar);
        var reviewerAuth = authentication.Require(reviewer);
        if (registrarAuth.Kind != "OIDC_ACR_ASSERTED" ||
            reviewerAuth.Kind != "OIDC_ACR_ASSERTED" ||
            registrarAuth.AuthenticationTimeUnix is not { } registrarTime ||
            reviewerAuth.AuthenticationTimeUnix is not { } reviewerTime)
            throw new UnauthorizedAccessException("Independent fresh authentication is required.");

        // Both live results must pass BEFORE either directory query; do not
        // make a positive inference from a revoked token or stale role claims.
        await RequireLive(registrarToken!, policy.RegistrarAudience, registrar,
            "platform_credential_registrar", ct);
        await RequireLive(reviewerToken!, policy.ReviewerAudience, reviewer,
            "platform_approver", ct);

        // Effective directory role is independently fetched from Keycloak
        // Admin REST (or future separately reviewed provider adapter).
        await RequireCurrent(registrar, "platform_credential_registrar", ct);
        await RequireCurrent(reviewer, "platform_approver", ct);

        return new RegistrarIdentityPreflight(policy.Issuer,
            registrar.Subject, reviewer.Subject, registrarTime, reviewerTime);
    }

    private void RequireSigned(VerifiedOidcToken principal, string role)
    {
        if (principal is null || principal.Issuer != policy.Issuer ||
            !ValidSubject(principal.Subject) ||
            principal.Roles is null ||
            !principal.Roles.Contains(role, StringComparer.Ordinal))
            throw new UnauthorizedAccessException("Incorrect signed issuer, subject or role.");
    }

    private async Task RequireLive(
        string accessToken, string audience, VerifiedOidcToken signed,
        string role, CancellationToken ct)
    {
        var state = await live.CheckAsync(accessToken, audience, ct);
        if (state is null || !state.Active ||
            state.Issuer != policy.Issuer ||
            state.Subject != signed.Subject ||
            state.Audiences is null ||
            !state.Audiences.Contains(audience, StringComparer.Ordinal) ||
            state.Roles is null ||
            !state.Roles.Contains(role, StringComparer.Ordinal))
            throw new UnauthorizedAccessException("Live IdP token state denied registration.");
    }

    private async Task RequireCurrent(
        VerifiedOidcToken signed, string role, CancellationToken ct)
    {
        var account = await directory.GetAccountAsync(policy.Issuer, signed.Subject, ct);
        if (account is null || !account.Enabled ||
            account.Issuer != policy.Issuer ||
            account.Subject != signed.Subject ||
            account.EffectiveRealmRoles is null ||
            !account.EffectiveRealmRoles.Contains(role, StringComparer.Ordinal))
            throw new UnauthorizedAccessException("Current IdP principal or role denied registration.");
    }

    private static bool ValidSubject(string? value) =>
        !string.IsNullOrWhiteSpace(value) && value.Length <= 255 &&
        value == value.Trim() && !value.Any(char.IsControl);

    private static bool ValidBearer(string? token) =>
        !string.IsNullOrWhiteSpace(token) && token.Length <= 16384 &&
        token == token.Trim() && !token.Any(char.IsWhiteSpace);
}
