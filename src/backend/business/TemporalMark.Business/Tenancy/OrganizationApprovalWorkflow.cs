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
    string ApproverSubject, string ApprovalProofHashHex);

public interface IOrganizationApprovalStore
{
    Task<Guid> RequestAsync(VerifiedOrganizationEnrollment request, CancellationToken ct);
    Task<Guid> ApproveAsync(VerifiedOrganizationApproval approval, CancellationToken ct);
    Task<Guid> CompleteAsync(VerifiedOrganizationEnrollment completion, CancellationToken ct);
}

/// <summary>
/// Privileged non-HTTP request -> independent approval -> enrollment flow.
/// Signature and fresh live-status checks are required for all three principals.
/// </summary>
public sealed class OrganizationApprovalWorkflow(
    IVerifiedOidcTokenSource verifier,
    ILiveOidcTokenStatus liveStatus,
    IOrganizationApprovalStore store,
    ProvisioningPolicy policy,
    string approverAudience)
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
        if (identity.Subject == expectedOperatorSubject || identity.Subject == expectedAdminSubject ||
            expectedOperatorSubject == expectedAdminSubject)
            throw new UnauthorizedAccessException("Approver, operator and admin must be distinct.");

        await CheckLiveAsync(approverToken, approverAudience, identity, "platform_approver", ct);
        var entry = new VerifiedOrganizationApproval(
            requestId, organizationName, identity.Issuer, expectedOperatorSubject,
            expectedAdminSubject, identity.Subject, HashToken(approverToken));
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
