using Npgsql;
using TemporalMark.Business.Tenancy;
using TemporalMark.Infrastructure.Postgres;
using TemporalMark.Provisioner;

// Standalone privileged operator executable; NOT hosted by API/PWA.
// Commands intentionally bind a request to EXACT name + operator/admin identities.
// Identity proofs must be protected owner-only files, never command arguments.
try
{
    if (args.Length == 0) throw new ArgumentException("Request, approve or complete mode required.");
    var mode = args[0];
    var issuer = Environment.GetEnvironmentVariable("PROVISIONING_OIDC_ISSUER")
        ?? throw new InvalidOperationException("PROVISIONING_OIDC_ISSUER required.");
    var localHttp = Environment.GetEnvironmentVariable("PROVISIONING_ALLOW_HTTP_LOOPBACK") == "true";
    if (Environment.GetEnvironmentVariable("PROVISIONING_LIVE_PROVIDER") != "keycloak")
        throw new InvalidOperationException("A supported live identity provider is required.");
    var clientId = Environment.GetEnvironmentVariable("PROVISIONING_INTROSPECTION_CLIENT_ID")
        ?? throw new InvalidOperationException("Confidential introspection client ID required.");
    var clientSecret = Environment.GetEnvironmentVariable("PROVISIONING_INTROSPECTION_CLIENT_SECRET")
        ?? throw new InvalidOperationException("Confidential introspection secret required.");
    var operatorAudience = Environment.GetEnvironmentVariable("PROVISIONING_OPERATOR_AUDIENCE")
        ?? "temporalmark-provisioner";
    var adminAudience = Environment.GetEnvironmentVariable("PROVISIONING_ADMIN_AUDIENCE")
        ?? "temporalmark-api";
    var approverAudience = Environment.GetEnvironmentVariable("PROVISIONING_APPROVER_AUDIENCE")
        ?? "temporalmark-approval";

    using var live = new KeycloakTokenIntrospector(issuer, localHttp, clientId, clientSecret);
    // Independent current account+effective realm-role lookup is mandatory.
    // Missing client credentials must NEVER degrade to JWT/introspection-only.
    var directoryClientId = Environment.GetEnvironmentVariable("PROVISIONING_DIRECTORY_CLIENT_ID")
        ?? throw new InvalidOperationException("Directory service client ID required.");
    var directorySecret = Environment.GetEnvironmentVariable("PROVISIONING_DIRECTORY_CLIENT_SECRET")
        ?? throw new InvalidOperationException("Directory service client secret required.");
    using var directory = new KeycloakCurrentAccountDirectory(
        issuer, localHttp, directoryClientId, directorySecret);
    var verifier = new OidcAccessTokenVerifier(issuer, localHttp);
    var policy = new ProvisioningPolicy(issuer.TrimEnd('/'), operatorAudience, adminAudience);

    // Approvers MUST NOT use the provisioning SQL login; the database itself
    // enforces approve-only versus request/complete-only EXECUTE permissions.
    var connection = mode == "approve"
        ? Environment.GetEnvironmentVariable("TEMPORALMARK_APPROVER_DB")
        : Environment.GetEnvironmentVariable("TEMPORALMARK_PROVISIONING_DB");
    if (string.IsNullOrWhiteSpace(connection))
        throw new InvalidOperationException("Dedicated action-specific DB credential required.");
    await using var db = NpgsqlDataSource.Create(connection);
    var flow = new OrganizationApprovalWorkflow(
        verifier, live, directory, new PostgresOrganizationApprovalStore(db), policy, approverAudience);

    Guid result;
    switch (mode)
    {
        case "request" when args.Length == 7 &&
            args[1] == "--organization-name" && args[3] == "--operator-token-file" &&
            args[5] == "--first-admin-token-file":
            result = await flow.RequestAsync(args[2],
                await ReadProtectedTokenFile(args[4]),
                await ReadProtectedTokenFile(args[6]), default);
            Console.WriteLine($"Approval requested: {result:D}");
            Console.WriteLine("Use a separately authenticated platform approver to review exact name, issuer and subjects.");
            break;
        case "approve" when args.Length == 11 &&
            args[1] == "--request-id" && args[3] == "--organization-name" &&
            args[5] == "--expected-initial-admin-sub" && args[7] == "--expected-operator-sub" &&
            args[9] == "--approver-token-file":
            result = await flow.ApproveAsync(ParseId(args[2]), args[4], args[6], args[8],
                await ReadProtectedTokenFile(args[10]), default);
            Console.WriteLine($"Approval recorded: {result:D}");
            break;
        case "complete" when args.Length == 9 &&
            args[1] == "--request-id" && args[3] == "--organization-name" &&
            args[5] == "--operator-token-file" && args[7] == "--first-admin-token-file":
            result = await flow.CompleteAsync(ParseId(args[2]), args[4],
                await ReadProtectedTokenFile(args[6]),
                await ReadProtectedTokenFile(args[8]), default);
            Console.WriteLine($"Organization created: {result:D}");
            Console.WriteLine("IdP organization claim mapping and operational reconciliation are still required.");
            break;
        default:
            throw new ArgumentException(
                "Usage: request --organization-name NAME --operator-token-file PATH --first-admin-token-file PATH | " +
                "approve --request-id UUID --organization-name NAME --expected-initial-admin-sub SUB " +
                "--expected-operator-sub SUB --approver-token-file PATH | " +
                "complete --request-id UUID --organization-name NAME --operator-token-file PATH " +
                "--first-admin-token-file PATH");
    }
    return 0;
}
catch (Exception exception)
{
    // No token or SQL detail in terminal logs; status only.
    Console.Error.WriteLine($"Provisioning refused ({exception.GetType().Name}). Consult operator runbook.");
    return 1;
}

static Guid ParseId(string text) =>
    Guid.TryParse(text, out var id) && id != Guid.Empty ? id :
        throw new ArgumentException("A nonempty approval request UUID is required.");

static async Task<string> ReadProtectedTokenFile(string path)
{
    if (!File.Exists(path) || File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
        throw new UnauthorizedAccessException("Token file must be a regular protected file.");
    if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
    {
        var permissions = File.GetUnixFileMode(path);
        const UnixFileMode prohibited = UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
            UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
            UnixFileMode.OtherExecute;
        if ((permissions & prohibited) != 0)
            throw new UnauthorizedAccessException("Token files may be read only by their owner.");
    }
    if (new FileInfo(path).Length > 16384)
        throw new UnauthorizedAccessException("Token file is too large.");
    return (await File.ReadAllTextAsync(path)).TrimEnd('\r', '\n');
}
