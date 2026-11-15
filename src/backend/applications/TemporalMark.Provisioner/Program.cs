using Npgsql;
using TemporalMark.Business.Tenancy;
using TemporalMark.Infrastructure.Postgres;
using TemporalMark.Provisioner;

// Standalone operator executable; not hosted by the public API or PWA.
// NO tokens, passwords or arbitrary first-admin subject in process arguments.
try
{
    if (args.Length != 6 || args[0] != "--organization-name" ||
        args[2] != "--operator-token-file" || args[4] != "--first-admin-token-file")
        throw new ArgumentException(
            "Usage: --organization-name NAME --operator-token-file PATH --first-admin-token-file PATH");
    var issuer = Environment.GetEnvironmentVariable("PROVISIONING_OIDC_ISSUER")
        ?? throw new InvalidOperationException("PROVISIONING_OIDC_ISSUER is required.");
    var connection = Environment.GetEnvironmentVariable("TEMPORALMARK_PROVISIONING_DB")
        ?? throw new InvalidOperationException("TEMPORALMARK_PROVISIONING_DB is required.");
    var operatorAudience = Environment.GetEnvironmentVariable("PROVISIONING_OPERATOR_AUDIENCE")
        ?? "temporalmark-provisioner";
    var adminAudience = Environment.GetEnvironmentVariable("PROVISIONING_ADMIN_AUDIENCE")
        ?? "temporalmark-api";
    var localHttp = Environment.GetEnvironmentVariable("PROVISIONING_ALLOW_HTTP_LOOPBACK") == "true";
    var verifier = new OidcAccessTokenVerifier(issuer, localHttp);
    var policy = new ProvisioningPolicy(issuer.TrimEnd('/'), operatorAudience, adminAudience);
    await using var db = NpgsqlDataSource.Create(connection);
    var operatorToken = await ReadProtectedTokenFile(args[3]);
    var adminToken = await ReadProtectedTokenFile(args[5]);
    var service = new OrganizationProvisioningService(
        verifier, new PostgresOrganizationProvisioningStore(db), policy);
    var organization = await service.CreateAsync(args[1], operatorToken, adminToken, default);
    Console.WriteLine($"Organization created: {organization:D}");
    Console.WriteLine("Operator must now configure the new organization's verified IdP claim mapping.");
    return 0;
}
catch (Exception exception)
{
    // Never expose credential values, token contents or untrusted database error details.
    Console.Error.WriteLine($"Provisioning refused ({exception.GetType().Name}). Consult operator runbook.");
    return 1;
}

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
