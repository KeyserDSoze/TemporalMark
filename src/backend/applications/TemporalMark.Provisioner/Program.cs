using Npgsql;
using TemporalMark.Business.Tenancy;
using TemporalMark.Infrastructure.Postgres;
using TemporalMark.Provisioner;

// Standalone privileged operator executable; NOT hosted by API/PWA.
// Commands intentionally bind a request to EXACT name + operator/admin identities.
// Identity proofs must be protected owner-only files, never command arguments.
try
{
    if (args.Length == 0) throw new ArgumentException("Registrar-intent, request, review, challenge, approve, reject or complete mode required.");
    // Separate hardened registrar operation. It NEVER shares provisioning or
    // approver SQL logins, password-only fixture exceptions, or arbitrary RP
    // ID/issuer/subject values from command-line arguments.
    if (args[0] == "registrar-intent")
        return await IssueUnconsumableRegistrarIntentAsync(args);
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
    var requiredApproverAcr = Environment.GetEnvironmentVariable("PROVISIONING_APPROVER_REQUIRED_ACR")
        ?? throw new InvalidOperationException("Pinned OIDC approval ACR configuration required.");
    // Exception only for the exact disposable Keycloak fixture, never generic loopback
    // or HTTPS deployments. The fixture has NO MFA and is not a release test.
    var allowDisposableNoMfa =
        localHttp &&
        issuer.TrimEnd('/') == ApprovalAuthenticationPolicy.DisposableLocalIssuer &&
        Environment.GetEnvironmentVariable("PROVISIONING_DEVELOPMENT_PASSWORD_GRANT_NO_MFA") == "true";
    var approverAuthentication = new ApprovalAuthenticationPolicy(
        requiredApproverAcr, TimeSpan.FromSeconds(120), allowDisposableNoMfa);

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
    var connection = mode is "approve" or "review" or "reject" or "challenge"
        ? Environment.GetEnvironmentVariable("TEMPORALMARK_APPROVER_DB")
        : Environment.GetEnvironmentVariable("TEMPORALMARK_PROVISIONING_DB");
    if (string.IsNullOrWhiteSpace(connection))
        throw new InvalidOperationException("Dedicated action-specific DB credential required.");
    await using var db = NpgsqlDataSource.Create(connection);
    var flow = new OrganizationApprovalWorkflow(
        verifier, live, directory, new PostgresOrganizationApprovalStore(db), policy,
        approverAudience, approverAuthentication);

    // Reviewed data comes from the restricted SQL function, never user argv.
    if (mode == "review" && args.Length == 5 &&
        args[1] == "--request-id" && args[3] == "--approver-token-file")
    {
        var snapshot = await flow.ReviewAsync(ParseId(args[2]),
            await ReadProtectedTokenFile(args[4]), default);
        Console.WriteLine($"Review request: {snapshot.RequestId:D}");
        Console.WriteLine($"Organization: {snapshot.OrganizationName}");
        Console.WriteLine($"Issuer: {snapshot.IdentityIssuer}");
        Console.WriteLine($"Operator subject: {snapshot.OperatorSubject}");
        Console.WriteLine($"Initial admin subject: {snapshot.FirstAdminSubject}");
        Console.WriteLine($"Expires UTC: {snapshot.ExpiresUtc.UtcDateTime:O}");
        Console.WriteLine($"Review SHA-256: {snapshot.ReviewSha256}");
        Console.WriteLine("This digest is NOT a signed or independently witnessed human decision.");
        return 0;
    }

    // Issuing a challenge is NOT approval or rejection. No browser WebAuthn
    // assertion is accepted until an independently audited verifier exists.
    if (mode == "challenge" && args.Length == 11 &&
        args[1] == "--request-id" && args[3] == "--review-sha256" &&
        args[5] == "--decision" && args[7] == "--reason-code" &&
        args[9] == "--approver-token-file")
    {
        var reason = args[8] == "NONE" ? null : args[8];
        var challenge = await flow.IssueDecisionChallengeAsync(
            ParseId(args[2]), args[4], args[6], reason,
            await ReadProtectedTokenFile(args[10]), default);
        Console.WriteLine($"Decision challenge issued: {challenge.ChallengeId:D}");
        Console.WriteLine($"Request: {challenge.RequestId:D}");
        Console.WriteLine($"Review SHA-256: {challenge.ReviewSha256}");
        Console.WriteLine($"Reviewer: {challenge.ReviewerSubject}");
        Console.WriteLine($"Decision intent: {challenge.Decision}");
        Console.WriteLine($"Reason code: {challenge.ReasonCode ?? "NONE"}");
        Console.WriteLine($"Challenge hex: {challenge.ChallengeHex}");
        Console.WriteLine($"Challenge expires UTC: {challenge.ExpiresUtc.UtcDateTime:O}");
        Console.WriteLine("UNSIGNED CHALLENGE ONLY — no organization was approved or rejected.");
        return 0;
    }

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
        case "approve" when args.Length == 7 &&
            args[1] == "--request-id" && args[3] == "--review-sha256" &&
            args[5] == "--approver-token-file":
            result = await flow.ApproveReviewedAsync(ParseId(args[2]), args[4],
                await ReadProtectedTokenFile(args[6]), default);
            Console.WriteLine($"Approval recorded: {result:D}");
            break;
        case "reject" when args.Length == 9 &&
            args[1] == "--request-id" && args[3] == "--review-sha256" &&
            args[5] == "--reason-code" && args[7] == "--approver-token-file":
            result = await flow.RejectReviewedAsync(ParseId(args[2]), args[4],
                args[6], await ReadProtectedTokenFile(args[8]), default);
            Console.WriteLine($"Enrollment rejected: {result:D}");
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
                "review --request-id UUID --approver-token-file PATH | " +
                "challenge --request-id UUID --review-sha256 HEX --decision APPROVE|REJECT " +
                "--reason-code CODE|NONE --approver-token-file PATH | " +
                "approve --request-id UUID --review-sha256 HEX --approver-token-file PATH | " +
                "reject --request-id UUID --review-sha256 HEX --reason-code CODE " +
                "--approver-token-file PATH | " +
                "complete --request-id UUID --organization-name NAME --operator-token-file PATH " +
                "--first-admin-token-file PATH");
    }
    return 0;
}
catch (UnauthorizedAccessException) when (args.Length > 0 && args[0] == "registrar-intent")
{
    // Intentionally clear release stop-line. Do not output token contents,
    // SQL credentials, or a config hint that could bypass the interlock.
    Console.Error.WriteLine(
        "V015 registrar intent issuance suspended: signed one-time WebAuthn registration is not implemented.");
    return 1;
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


static async Task<int> IssueUnconsumableRegistrarIntentAsync(string[] argv)
{
    if (argv.Length != 5 ||
        argv[1] != "--registrar-token-file" ||
        argv[3] != "--reviewer-token-file")
        throw new ArgumentException(
            "Usage: registrar-intent --registrar-token-file PATH --reviewer-token-file PATH. " +
            "RP, issuer and expected reviewer are pinned configuration, not arguments.");

    // V015 revokes SQL registrar issuance and this explicit CLI gate refuses
    // BEFORE reading JWT files, contacting an IdP or opening any SQL login.
    // Never add a secret/environment override. A future signed and consumed
    // ceremony requires a NEW operator command and reviewed SQL function.
    EnforceRegistrarV015ReleaseInterlock();

    // This command is standalone operator-only and deliberately never runs
    // against the Docker HTTP MFA realm or password-only development issuer.
    // No Keycloak/SQL role, registrar login, owner policy, or credential key
    // is installed automatically by merely invoking it.
    static string Require(string key) =>
        Environment.GetEnvironmentVariable(key) is { Length: > 0 } value
            ? value : throw new InvalidOperationException(
                "Required explicitly approved registrar configuration missing: " + key);

    if (Require("REGISTRAR_LIVE_PROVIDER") != "keycloak")
        throw new InvalidOperationException("Only the reviewed Keycloak registrar provider is supported.");
    var issuer = Require("REGISTRAR_OIDC_ISSUER");
    var registrarAudience = Require("REGISTRAR_AUDIENCE");
    var reviewerAudience = Require("REGISTRAR_REVIEWER_AUDIENCE");
    var requiredAcr = Require("REGISTRAR_REQUIRED_ACR");
    var policy = new RegistrarIdentityGatePolicy(
        issuer, registrarAudience, reviewerAudience, requiredAcr);
    var rp = new RegistrarIntentDeploymentPolicy(
        issuer, Require("REGISTRAR_RP_ID"),
        Require("REGISTRAR_ORIGIN"),
        Require("REGISTRAR_APPROVED_REVIEWER_SUBJECT"));

    // Production-only HTTPS: no local development bypass is passed to any
    // token, live-introspection, directory or pinned deployment policy.
    var verifier = new OidcAccessTokenVerifier(issuer, permitLocalDevelopmentHttp: false);
    using var live = new KeycloakTokenIntrospector(
        issuer, allowLocalHttp: false,
        Require("REGISTRAR_INTROSPECTION_CLIENT_ID"),
        Require("REGISTRAR_INTROSPECTION_CLIENT_SECRET"));
    using var directory = new KeycloakCurrentAccountDirectory(
        issuer, allowLocalHttp: false,
        Require("REGISTRAR_DIRECTORY_CLIENT_ID"),
        Require("REGISTRAR_DIRECTORY_CLIENT_SECRET"));
    var gate = new ReviewerCredentialRegistrarIdentityGate(
        verifier, live, directory, policy);

    await using var dedicatedDb = NpgsqlDataSource.Create(Require("TEMPORALMARK_REGISTRAR_DB"));
    var store = new PostgresReviewerRegistrationIntentStore(
        dedicatedDb, Require("REGISTRAR_EXPECTED_SQL_LOGIN"));
    var flow = new ReviewerRegistrationIntentWorkflow(gate, store, rp);
    var issued = await flow.IssueAsync(
        await ReadProtectedTokenFile(argv[2]),
        await ReadProtectedTokenFile(argv[4]), CancellationToken.None);

    Console.WriteLine($"Registration intent ID: {issued.IntentId:D}");
    Console.WriteLine($"Pinned issuer: {issued.IdentityIssuer}");
    Console.WriteLine($"RP ID: {issued.RelyingPartyId}");
    Console.WriteLine($"Origin: {issued.TrustedOrigin}");
    Console.WriteLine($"Reviewer subject: {issued.ReviewerSubject}");
    Console.WriteLine($"Registrar subject: {issued.RegistrarSubject}");
    Console.WriteLine($"Challenge hex: {issued.ChallengeHex}");
    Console.WriteLine($"Intent expires UTC: {issued.ExpiresUtc.UtcDateTime:O}");
    Console.WriteLine("UNCONSUMABLE REGISTRATION INTENT ONLY — no key, WebAuthn attestation, " +
        "tenant approval, or qualified legal evidence.");
    return 0;
}

static void EnforceRegistrarV015ReleaseInterlock() =>
    throw new UnauthorizedAccessException(
        "V015 registrar issuance is suspended until independently signed, consumed WebAuthn registration is implemented.");
