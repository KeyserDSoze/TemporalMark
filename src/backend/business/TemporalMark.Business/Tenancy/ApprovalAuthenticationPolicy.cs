namespace TemporalMark.Business.Tenancy;

/// <summary>
/// Validates authentication context taken ONLY from a cryptographically verified
/// OIDC access token. Requires deployment evidence that a pinned ACR genuinely
/// maps to a two-factor Keycloak step-up flow; the ACR string alone is NOT MFA.
/// </summary>
public interface IApprovalAuthenticationPolicy
{
    void Require(VerifiedOidcToken verifiedApprover);
}

public sealed class ApprovalAuthenticationPolicy : IApprovalAuthenticationPolicy
{
    public const string DisposableLocalIssuer = "http://localhost:8081/realms/temporalmark";
    public const string DisposableApproverSubject = "00000000-0000-0000-0000-000000000004";
    private readonly string requiredAcr;
    private readonly long maximumAgeSeconds;
    private readonly bool allowDisposableFixture;
    private readonly TimeProvider time;

    public ApprovalAuthenticationPolicy(string requiredAcr, TimeSpan maximumAge,
        bool allowPasswordOnlyDisposableLocalFixture = false,
        TimeProvider? timeProvider = null)
    {
        if (string.IsNullOrWhiteSpace(requiredAcr) ||
            requiredAcr.Length > 255 || requiredAcr != requiredAcr.Trim() ||
            requiredAcr.Any(char.IsControl) ||
            new[] { "0", "1", "pwd", "password", "basic" }
                .Contains(requiredAcr, StringComparer.OrdinalIgnoreCase))
            throw new ArgumentException("An explicitly configured non-password-only ACR is required.",
                nameof(requiredAcr));
        if (maximumAge <= TimeSpan.Zero || maximumAge > TimeSpan.FromSeconds(120) ||
            maximumAge.Ticks % TimeSpan.TicksPerSecond != 0)
            throw new ArgumentOutOfRangeException(nameof(maximumAge),
                "Approver authentication age must be 1–120 whole seconds.");

        this.requiredAcr = requiredAcr;
        maximumAgeSeconds = (long)maximumAge.TotalSeconds;
        allowDisposableFixture = allowPasswordOnlyDisposableLocalFixture;
        time = timeProvider ?? TimeProvider.System;
    }

    public void Require(VerifiedOidcToken verifiedApprover)
    {
        if (verifiedApprover is null)
            throw new UnauthorizedAccessException("Missing validated approver identity.");

        // Development exception is restricted to this single hardcoded disposable
        // loopback issuer AND known test account, never a configurable realm/subject.
        // This fixture uses PASSWORD GRANT, and does NOT demonstrate MFA.
        if (allowDisposableFixture &&
            verifiedApprover.Issuer == DisposableLocalIssuer &&
            verifiedApprover.Subject == DisposableApproverSubject)
            return;

        var now = time.GetUtcNow().ToUnixTimeSeconds();
        if (verifiedApprover.AuthenticationContext != requiredAcr ||
            verifiedApprover.AuthenticationTimeUnix is not { } authTime ||
            verifiedApprover.IssuedAtUnix is not { } issuedAt ||
            authTime > now + 30 ||
            authTime < now - maximumAgeSeconds ||
            authTime > issuedAt + 30 ||
            issuedAt > now + 30 ||
            issuedAt < now - 300)
            throw new UnauthorizedAccessException(
                "Approved, recent OIDC authentication assurance is required.");
    }
}
