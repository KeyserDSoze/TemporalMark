using System.Security.Cryptography;
using System.Text;

namespace TemporalMark.Business.Tenancy;

/// <summary>Identity returned only after cryptographic access-token validation against a pinned IdP.</summary>
public sealed record VerifiedOidcToken(string Issuer, string Subject, IReadOnlyCollection<string> Roles);

public sealed record ProvisioningPolicy(string Issuer, string OperatorAudience, string AdminAudience);

public interface IVerifiedOidcTokenSource
{
    Task<VerifiedOidcToken> VerifyAsync(string accessToken, string expectedAudience, CancellationToken cancellationToken);
}

public sealed record VerifiedOrganizationEnrollment(
    Guid OrganizationId,
    string OrganizationName,
    string IdentityIssuer,
    string FirstAdminSubject,
    string ProvisionerSubject,
    string OperatorProofHashHex,
    string AdminProofHashHex);

public interface IOrganizationProvisioningStore
{
    Task CreateAsync(VerifiedOrganizationEnrollment enrollment, CancellationToken cancellationToken);
}

/// <summary>
/// Deliberately not exposed over HTTP. Two distinct, verified IdP principals and
/// a narrow database credential are required; no arbitrary admin-subject input.
/// </summary>
public sealed class OrganizationProvisioningService(
    IVerifiedOidcTokenSource verifier,
    IOrganizationProvisioningStore storage,
    ProvisioningPolicy policy)
{
    public async Task<Guid> CreateAsync(
        string organizationName,
        string operatorAccessToken,
        string firstAdminAccessToken,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(organizationName) || organizationName.Length > 200 ||
            organizationName != organizationName.Trim() || organizationName.Any(char.IsControl))
            throw new ArgumentException("A safe, bounded organization name is required.", nameof(organizationName));
        RequireToken(operatorAccessToken, nameof(operatorAccessToken));
        RequireToken(firstAdminAccessToken, nameof(firstAdminAccessToken));
        if (operatorAccessToken == firstAdminAccessToken)
            throw new UnauthorizedAccessException("Two independent credentials are required.");

        var operatorIdentity = await verifier.VerifyAsync(operatorAccessToken, policy.OperatorAudience, cancellationToken);
        var adminIdentity = await verifier.VerifyAsync(firstAdminAccessToken, policy.AdminAudience, cancellationToken);

        if (operatorIdentity.Issuer != policy.Issuer || adminIdentity.Issuer != policy.Issuer ||
            !ValidSubject(operatorIdentity.Subject) || !ValidSubject(adminIdentity.Subject) ||
            operatorIdentity.Subject == adminIdentity.Subject ||
            !operatorIdentity.Roles.Contains("platform_provisioner", StringComparer.Ordinal) ||
            !adminIdentity.Roles.Contains("tenant_admin", StringComparer.Ordinal))
            throw new UnauthorizedAccessException("Validated OIDC identities lack the required permissions or issuer.");

        var enrollment = new VerifiedOrganizationEnrollment(
            Guid.NewGuid(), organizationName, policy.Issuer, adminIdentity.Subject, operatorIdentity.Subject,
            HashToken(operatorAccessToken), HashToken(firstAdminAccessToken));
        await storage.CreateAsync(enrollment, cancellationToken);
        return enrollment.OrganizationId;
    }

    private static void RequireToken(string? token, string param)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > 16384 ||
            token != token.Trim() || token.Any(char.IsWhiteSpace))
            throw new ArgumentException("A compact access token is required.", param);
    }

    private static bool ValidSubject(string? sub) =>
        !string.IsNullOrWhiteSpace(sub) && sub.Length <= 255 && sub == sub.Trim() &&
        !sub.Any(char.IsControl);

    private static string HashToken(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(token)));
}
