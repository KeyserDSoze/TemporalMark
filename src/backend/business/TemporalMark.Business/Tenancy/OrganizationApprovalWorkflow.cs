using System.Security.Cryptography;
using System.Text;

namespace TemporalMark.Business.Tenancy;

/// <summary>
/// A scope confirmed by a distinct, live OIDC approver. PostgreSQL must
/// cross-check its fields against the requested organization, not trust the CLI.
/// </summary>
public sealed record VerifiedOrganizationApproval(
    Guid OrganizationId, string ExpectedOrganizationName, string IdentityIssuer,
    string ExpectedOperatorSubject, string ExpectedAdminSubject,
    string ApproverSubject, string ApprovalProofHashHex,
    ApprovalAuthenticationEvidence AuthenticationEvidence);

/// <summary>A terminal, scope-bound rejection; NOT a signed human consent artifact.</summary>
public sealed record VerifiedOrganizationRejection(
    Guid OrganizationId, string ExpectedOrganizationName, string IdentityIssuer,
    string ExpectedOperatorSubject, string ExpectedAdminSubject,
    string ReviewerSubject, string ReviewerProofHashHex,
    string ReviewSha256, string ReasonCode);

/// <summary>
/// A pending WebAuthn challenge request. This is NOT an authorization/decision.
/// Future verifier must bind an independently enrolled reviewer-held credential.
/// </summary>
public sealed record VerifiedReviewerDecisionChallengeRequest(
    PendingOrganizationReview Scope, string ReviewerSubject,
    string Decision, string? ReasonCode);

/// <summary>
/// Database-issued random challenge, with no signature or effect on the
/// enrollment. A successful issue MUST NOT imply APPROVED or REJECTED.
/// </summary>
public sealed record IssuedReviewerDecisionChallenge(
    Guid ChallengeId, Guid RequestId, string ReviewSha256, string IdentityIssuer,
    string ReviewerSubject, string Decision, string? ReasonCode,
    string ChallengeHex, DateTimeOffset IssuedUtc, DateTimeOffset ExpiresUtc);

/// <summary>Current directory state, not claims snapshotted in the JWT.</summary>
public sealed record CurrentOidcAccount(string Issuer, string Subject, bool Enabled,
    IReadOnlyCollection<string> EffectiveRealmRoles);

public interface ICurrentOidcAccountDirectory
{
    Task<CurrentOidcAccount> GetAccountAsync(string issuer, string subject, CancellationToken ct);
}

/// <summary>
/// Exact pending record returned by the APPROVER-ONLY database routine.
/// The hash binds fields unambiguously; it does NOT sign a human decision.
/// </summary>
public sealed record PendingOrganizationReview(
    Guid RequestId, string OrganizationName, string IdentityIssuer,
    string OperatorSubject, string FirstAdminSubject, DateTimeOffset ExpiresUtc)
{
    public string ReviewSha256 => ComputeReviewSha256();

    private string ComputeReviewSha256()
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(Encoding.ASCII.GetBytes("TemporalMark.PendingReview.v1\\0".Replace("\\0", "\0")));
        Span<byte> length = stackalloc byte[4];
        foreach (var value in new[]
        {
            RequestId.ToString("D"), OrganizationName, IdentityIssuer,
            OperatorSubject, FirstAdminSubject,
            ExpiresUtc.UtcDateTime.Ticks.ToString(System.Globalization.CultureInfo.InvariantCulture)
        })
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(length, bytes.Length);
            hash.AppendData(length);
            hash.AppendData(bytes);
        }
        return Convert.ToHexString(hash.GetHashAndReset());
    }
}

public interface IOrganizationApprovalStore
{
    Task<Guid> RequestAsync(VerifiedOrganizationEnrollment request, CancellationToken ct);
    Task<PendingOrganizationReview?> ReadPendingReviewAsync(Guid requestId,
        string issuer, string reviewerSubject, CancellationToken ct);
    Task<Guid> ApproveAsync(VerifiedOrganizationApproval approval, CancellationToken ct);
    Task<Guid> RejectAsync(VerifiedOrganizationRejection rejection, CancellationToken ct);
    Task<IssuedReviewerDecisionChallenge> IssueDecisionChallengeAsync(
        VerifiedReviewerDecisionChallengeRequest request, CancellationToken ct);
    Task<Guid> CompleteAsync(VerifiedOrganizationEnrollment completion, CancellationToken ct);
}

/// <summary>
/// Privileged non-HTTP request -> independent approval -> enrollment flow.
/// Signature and fresh live-status checks are required for all three principals.
/// </summary>
public sealed class OrganizationApprovalWorkflow(
    IVerifiedOidcTokenSource verifier,
    ILiveOidcTokenStatus liveStatus,
    ICurrentOidcAccountDirectory directory,
    IOrganizationApprovalStore store,
    ProvisioningPolicy policy,
    string approverAudience,
    IApprovalAuthenticationPolicy approverAuthentication)
{
    public async Task<Guid> RequestAsync(
        string organizationName, string operatorToken, string adminToken, CancellationToken ct)
    {
        ValidateName(organizationName);
        var pair = await ValidatePairAsync(operatorToken, adminToken, ct);
        var entry = BuildEnrollment(Guid.NewGuid(), organizationName, operatorToken, adminToken, pair);
        var result = await store.RequestAsync(entry, ct);
        if (result != entry.OrganizationId) throw new InvalidOperationException("Approval request ID mismatch.");
        return result;
    }

    /// <summary>
    /// Authenticate the distinct reviewer before reading the ORIGINAL SQL request.
    /// No table-wide permission, caller-supplied name or operator-provided text.
    /// </summary>
    public async Task<PendingOrganizationReview> ReviewAsync(
        Guid requestId, string approverToken, CancellationToken ct)
    {
        ValidateRequestId(requestId);
        ValidateToken(approverToken);
        if (string.IsNullOrWhiteSpace(approverAudience) || approverAudience.Length > 255)
            throw new InvalidOperationException("Pinned approver audience required.");

        var identity = await verifier.VerifyAsync(approverToken, approverAudience, ct);
        RequireIdentity(identity, "platform_approver");
        approverAuthentication.Require(identity);
        await CheckLiveAsync(approverToken, approverAudience, identity, "platform_approver", ct);
        await RequireDirectoryRoleAsync(identity, "platform_approver", ct);
        var review = await store.ReadPendingReviewAsync(requestId, identity.Issuer, identity.Subject, ct);
        if (review is null || review.RequestId != requestId ||
            review.IdentityIssuer != policy.Issuer ||
            review.OperatorSubject == identity.Subject ||
            review.FirstAdminSubject == identity.Subject ||
            review.OperatorSubject == review.FirstAdminSubject ||
            review.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new UnauthorizedAccessException("No active independently reviewable request.");
        ValidateName(review.OrganizationName);
        ValidateSubject(review.OperatorSubject);
        ValidateSubject(review.FirstAdminSubject);
        return review;
    }

    /// <summary>
    /// Obtains a one-time, server-generated challenge bound to the original
    /// pending record. There is intentionally NO way to consume this challenge
    /// or to issue an approval using it without future signed WebAuthn proof.
    /// </summary>
    public async Task<IssuedReviewerDecisionChallenge> IssueDecisionChallengeAsync(
        Guid requestId, string reviewSha256, string decision, string? reasonCode,
        string approverToken, CancellationToken ct)
    {
        if (decision is not ("APPROVE" or "REJECT"))
            throw new ArgumentException("An exact APPROVE or REJECT action is required.", nameof(decision));
        if (decision == "APPROVE" && reasonCode is not null ||
            decision == "REJECT" && reasonCode is not
                ("UNVERIFIED_ORGANIZATION" or "UNVERIFIED_IDENTITY" or
                 "SCOPE_MISMATCH" or "POLICY_DENIED"))
            throw new ArgumentException("Only a bound, allowed reason can accompany rejection.",
                nameof(reasonCode));

        ValidateReviewHash(reviewSha256);
        var original = await ReviewAsync(requestId, approverToken, ct);
        RequireReviewHash(reviewSha256, original.ReviewSha256);

        // Do not use the identity from a caller-provided string. Revalidate
        // current signer claim, introspection and directory before issuance.
        var identity = await verifier.VerifyAsync(approverToken, approverAudience, ct);
        RequireIdentity(identity, "platform_approver");
        approverAuthentication.Require(identity);
        await CheckLiveAsync(approverToken, approverAudience, identity, "platform_approver", ct);
        await RequireDirectoryRoleAsync(identity, "platform_approver", ct);
        var issued = await store.IssueDecisionChallengeAsync(
            new VerifiedReviewerDecisionChallengeRequest(original, identity.Subject,
                decision, reasonCode), ct);
        if (issued.ChallengeId == Guid.Empty || issued.RequestId != requestId ||
            issued.ReviewSha256 != original.ReviewSha256 ||
            issued.IdentityIssuer != policy.Issuer ||
            issued.ReviewerSubject != identity.Subject ||
            issued.Decision != decision || issued.ReasonCode != reasonCode ||
            issued.ChallengeHex is null || issued.ChallengeHex.Length != 96 ||
            issued.ChallengeHex.Any(ch => !(ch is >= '0' and <= '9' or >= 'A' and <= 'F')) ||
            issued.ExpiresUtc <= issued.IssuedUtc ||
            issued.ExpiresUtc > issued.IssuedUtc.AddSeconds(60) ||
            issued.ExpiresUtc > original.ExpiresUtc ||
            issued.ExpiresUtc <= DateTimeOffset.UtcNow)
            throw new UnauthorizedAccessException("Decision challenge metadata is invalid.");
        return issued;
    }

    /// <summary>
    /// Terminal rejection after independently verifying the ORIGINAL pending scope.
    /// Reason codes are enumerated; never accept freeform potentially sensitive text.
    /// </summary>
    public async Task<Guid> RejectReviewedAsync(Guid requestId,
        string reviewSha256, string reasonCode, string approverToken, CancellationToken ct)
    {
        if (reasonCode is not ("UNVERIFIED_ORGANIZATION" or "UNVERIFIED_IDENTITY"
            or "SCOPE_MISMATCH" or "POLICY_DENIED"))
            throw new ArgumentException("Only approved rejection reason codes are accepted.",
                nameof(reasonCode));
        ValidateReviewHash(reviewSha256);
        var original = await ReviewAsync(requestId, approverToken, ct);
        RequireReviewHash(reviewSha256, original.ReviewSha256);

        // Re-evaluate privileges immediately before creating a terminal SQL
        // decision; a formerly valid reviewer role must not be silently cached.
        var identity = await verifier.VerifyAsync(approverToken, approverAudience, ct);
        RequireIdentity(identity, "platform_approver");
        approverAuthentication.Require(identity);
        await CheckLiveAsync(approverToken, approverAudience, identity, "platform_approver", ct);
        await RequireDirectoryRoleAsync(identity, "platform_approver", ct);
        var decision = new VerifiedOrganizationRejection(
            requestId, original.OrganizationName, original.IdentityIssuer,
            original.OperatorSubject, original.FirstAdminSubject,
            identity.Subject, HashToken(approverToken), original.ReviewSha256, reasonCode);
        var result = await store.RejectAsync(decision, ct);
        if (result != requestId) throw new InvalidOperationException("Rejected request ID mismatch.");
        return result;
    }

    private static void ValidateReviewHash(string reviewSha256)
    {
        if (reviewSha256 is null || reviewSha256.Length != 64 ||
            reviewSha256.Any(ch => !(ch is >= '0' and <= '9' or >= 'A' and <= 'F')))
            throw new UnauthorizedAccessException("A canonical uppercase review SHA-256 is required.");
    }

    private static void RequireReviewHash(string supplied, string original)
    {
        if (!CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(supplied), Convert.FromHexString(original)))
            throw new UnauthorizedAccessException("Reviewed scope differs from current pending request.");
    }

    /// <summary>
    /// Requires the reviewer to explicitly confirm the digest obtained from a
    /// fresh DB-backed read; this is not a reviewer-held cryptographic signature.
    /// </summary>
    public async Task<Guid> ApproveReviewedAsync(Guid requestId,
        string reviewSha256, string approverToken, CancellationToken ct)
    {
        ValidateReviewHash(reviewSha256);
        var review = await ReviewAsync(requestId, approverToken, ct);
        RequireReviewHash(reviewSha256, review.ReviewSha256);

        // Existing DB approval routine cross-checks issuer/name/all subjects
        // again and consumes only the original unexpired request.
        return await ApproveAsync(requestId, review.OrganizationName,
            review.FirstAdminSubject, review.OperatorSubject, approverToken, ct);
    }

    public async Task<Guid> ApproveAsync(Guid requestId, string organizationName,
        string expectedAdminSubject, string expectedOperatorSubject,
        string approverToken, CancellationToken ct)
    {
        ValidateRequestId(requestId);
        ValidateName(organizationName);
        ValidateSubject(expectedAdminSubject);
        ValidateSubject(expectedOperatorSubject);
        ValidateToken(approverToken);
        if (string.IsNullOrWhiteSpace(approverAudience) || approverAudience.Length > 255)
            throw new InvalidOperationException("A pinned approval audience is required.");

        var identity = await verifier.VerifyAsync(approverToken, approverAudience, ct);
        RequireIdentity(identity, "platform_approver");
        // No enrollment approval can rely on a signed role without recent
        // authentication context. The exact ACR must map to real MFA in the IdP.
        var assurance = approverAuthentication.Require(identity);
        if (identity.Subject == expectedOperatorSubject || identity.Subject == expectedAdminSubject ||
            expectedOperatorSubject == expectedAdminSubject)
            throw new UnauthorizedAccessException("Approver, operator and admin must be distinct.");

        await CheckLiveAsync(approverToken, approverAudience, identity, "platform_approver", ct);
        await RequireDirectoryRoleAsync(identity, "platform_approver", ct);
        var entry = new VerifiedOrganizationApproval(
            requestId, organizationName, identity.Issuer, expectedOperatorSubject,
            expectedAdminSubject, identity.Subject, HashToken(approverToken), assurance);
        var result = await store.ApproveAsync(entry, ct);
        if (result != requestId) throw new InvalidOperationException("Approval ID mismatch.");
        return result;
    }

    public async Task<Guid> CompleteAsync(Guid requestId, string organizationName,
        string operatorToken, string adminToken, CancellationToken ct)
    {
        ValidateRequestId(requestId);
        ValidateName(organizationName);
        var pair = await ValidatePairAsync(operatorToken, adminToken, ct);
        var entry = BuildEnrollment(requestId, organizationName, operatorToken, adminToken, pair);
        var result = await store.CompleteAsync(entry, ct);
        if (result != requestId) throw new InvalidOperationException("Completed organization ID mismatch.");
        return result;
    }

    private async Task<(VerifiedOidcToken Operator, VerifiedOidcToken Admin)> ValidatePairAsync(
        string operatorToken, string adminToken, CancellationToken ct)
    {
        ValidateToken(operatorToken);
        ValidateToken(adminToken);
        if (operatorToken == adminToken)
            throw new UnauthorizedAccessException("Operator and first admin must use separate credentials.");

        var op = await verifier.VerifyAsync(operatorToken, policy.OperatorAudience, ct);
        var admin = await verifier.VerifyAsync(adminToken, policy.AdminAudience, ct);
        RequireIdentity(op, "platform_provisioner");
        RequireIdentity(admin, "tenant_admin");
        if (op.Subject == admin.Subject)
            throw new UnauthorizedAccessException("A person cannot be both operator and first admin.");
        await CheckLiveAsync(operatorToken, policy.OperatorAudience, op, "platform_provisioner", ct);
        await CheckLiveAsync(adminToken, policy.AdminAudience, admin, "tenant_admin", ct);
        // Verify CURRENT effective realm role/account independently of JWT/introspection snapshots.
        await RequireDirectoryRoleAsync(op, "platform_provisioner", ct);
        await RequireDirectoryRoleAsync(admin, "tenant_admin", ct);
        return (op, admin);
    }

    private void RequireIdentity(VerifiedOidcToken identity, string role)
    {
        if (identity.Issuer != policy.Issuer || !ValidSubject(identity.Subject) ||
            identity.Roles is null || !identity.Roles.Contains(role, StringComparer.Ordinal))
            throw new UnauthorizedAccessException("The trusted OIDC issuer, subject or role is invalid.");
    }

    private async Task CheckLiveAsync(string token, string audience,
        VerifiedOidcToken signed, string requiredRole, CancellationToken ct)
    {
        var status = await liveStatus.CheckAsync(token, audience, ct);
        if (!status.Active || status.Issuer != policy.Issuer ||
            status.Subject != signed.Subject || status.Issuer != signed.Issuer ||
            status.Audiences is null || !status.Audiences.Contains(audience, StringComparer.Ordinal) ||
            status.Roles is null || !status.Roles.Contains(requiredRole, StringComparer.Ordinal))
            throw new UnauthorizedAccessException("Live OIDC status failed identity binding.");
    }

    private async Task RequireDirectoryRoleAsync(
        VerifiedOidcToken verified, string requiredRole, CancellationToken ct)
    {
        var current = await directory.GetAccountAsync(policy.Issuer, verified.Subject, ct);
        if (current is null || current.Issuer != policy.Issuer ||
            current.Subject != verified.Subject || !current.Enabled ||
            current.EffectiveRealmRoles is null ||
            !current.EffectiveRealmRoles.Contains(requiredRole, StringComparer.Ordinal))
            throw new UnauthorizedAccessException("Current OIDC directory identity or role denied.");
    }

    private VerifiedOrganizationEnrollment BuildEnrollment(
        Guid id, string name, string operatorToken, string adminToken,
        (VerifiedOidcToken Operator, VerifiedOidcToken Admin) pair) =>
        new(id, name, policy.Issuer, pair.Admin.Subject, pair.Operator.Subject,
            HashToken(operatorToken), HashToken(adminToken));

    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 200 || name != name.Trim()
            || name.Any(char.IsControl))
            throw new ArgumentException("A bounded, exact organization name is required.", nameof(name));
    }

    private static void ValidateSubject(string value)
    {
        if (!ValidSubject(value))
            throw new ArgumentException("An exact validated OIDC subject is required.");
    }

    private static bool ValidSubject(string? sub) =>
        !string.IsNullOrWhiteSpace(sub) && sub.Length <= 255 &&
        sub == sub.Trim() && !sub.Any(char.IsControl);

    private static void ValidateToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 16384 ||
            token != token.Trim() || token.Any(char.IsWhiteSpace))
            throw new ArgumentException("A compact, protected access token is required.");
    }

    private static void ValidateRequestId(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("An approved request ID is required.");
    }

    private static string HashToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
}
