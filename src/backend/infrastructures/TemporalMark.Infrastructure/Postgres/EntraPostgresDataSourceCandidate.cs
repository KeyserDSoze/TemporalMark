using System.Text.RegularExpressions;
using Npgsql;

namespace TemporalMark.Infrastructure.Postgres;

/// <summary>
/// #130 / ADR 0096. Detached Entra PostgreSQL data-source candidate, NOT wired
/// to the API, privileged CLI or migration job. No Azure SDK dependency.
/// The caller MUST provide a separately authorized Entra token credential.
/// </summary>
public static class EntraPostgresDataSourceCandidate
{
    // Microsoft Entra scope used by Azure Database for PostgreSQL Flexible Server.
    // This value is never selected by an HTTP caller, JWT or tenant.
    public const string PostgreSqlEntraScope =
        "https://ossrdbms-aad.database.windows.net/.default";

    private const string Failure = "Microsoft Entra PostgreSQL token acquisition failed";

    /// <summary>
    /// Builds a token-only data source. No socket or Azure token is acquired
    /// until the consumer attempts to open a new physical connection.
    /// Synchronous opens fail closed; async opens ask the supplied credential
    /// for the exact server scope on every new physical connection.
    /// </summary>
    public static NpgsqlDataSource Create(
        string connectionString,
        Func<string, CancellationToken, ValueTask<string>> requestEntraToken)
    {
        ArgumentNullException.ThrowIfNull(requestEntraToken);
        if (string.IsNullOrWhiteSpace(connectionString))
            throw new ArgumentException("An approved PostgreSQL connection configuration is required",
                nameof(connectionString));

        NpgsqlConnectionStringBuilder settings;
        try
        {
            settings = new NpgsqlConnectionStringBuilder(connectionString);
        }
        catch (ArgumentException)
        {
            // Parsing errors can include supplied values; never echo raw
            // connection-string syntax, password or private host in errors.
            throw new ArgumentException("Invalid PostgreSQL connection configuration",
                nameof(connectionString));
        }

        // No arbitrary DNS, server aliases, host lists, raw IPs or development
        // loopback for this candidate. Use canonical FQDN + private DNS CNAME.
        // The environment's actual private IP and certificate must be checked
        // separately on an approved VNet-connected Azure runner.
        if (settings.Host is not { } host ||
            !Regex.IsMatch(host,
                @"\A[a-z][a-z0-9-]{1,61}[a-z0-9]\.postgres\.database\.azure\.com\z",
                RegexOptions.CultureInvariant))
            throw new ArgumentException("An approved canonical Azure PostgreSQL host is required",
                nameof(connectionString));

        if (settings.Port != 5432 ||
            !settings.ContainsKey("Username") ||
            !settings.ContainsKey("Database") ||
            !Regex.IsMatch(settings.Username ?? "",
                @"\A[A-Za-z_][A-Za-z0-9_-]{1,62}\z", RegexOptions.CultureInvariant) ||
            !Regex.IsMatch(settings.Database ?? "",
                @"\A[a-z][a-z0-9_]{1,62}\z", RegexOptions.CultureInvariant))
            throw new ArgumentException("Explicit PostgreSQL role, database and port are required",
                nameof(connectionString));

        if (settings.ContainsKey("Password") || settings.ContainsKey("Passfile") ||
            settings.ContainsKey("Trust Server Certificate") ||
            settings.ContainsKey("SSL Certificate") ||
            settings.ContainsKey("SSL Key") ||
            settings.ContainsKey("SSL Password"))
            throw new ArgumentException("SQL passwords, passfiles and TLS bypasses are forbidden",
                nameof(connectionString));

        // Npgsql 10 can prefer GSSAPI over TLS by default. Require explicit
        // TLS VerifyFull, with GSS disabled, to enforce hostname verification.
        if (!settings.ContainsKey("SSL Mode") || settings.SslMode != SslMode.VerifyFull ||
            !settings.ContainsKey("GSS Encryption Mode") ||
            settings.GssEncryptionMode != GssEncryptionMode.Disable)
            throw new ArgumentException("Verified TLS and disabled GSS encryption are required",
                nameof(connectionString));

        var builder = new NpgsqlDataSourceBuilder(settings.ConnectionString);
        builder.UsePasswordProvider(
            _ => throw new NotSupportedException("Only asynchronous Entra PostgreSQL connections are supported"),
            (_, cancellationToken) => RequestTokenAsync(requestEntraToken, cancellationToken));
        return builder.Build();
    }

    /// <summary>
    /// Enforces the fixed audience and safe failure semantics independently
    /// of Azure network or an actual PostgreSQL socket; used by Npgsql's async
    /// password provider, not as a bearer-token logging or persistence API.
    /// </summary>
    public static async ValueTask<string> RequestTokenAsync(
        Func<string, CancellationToken, ValueTask<string>> requestEntraToken,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(requestEntraToken);
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var token = await requestEntraToken(PostgreSqlEntraScope, cancellationToken);
            if (string.IsNullOrWhiteSpace(token))
                throw new InvalidOperationException(Failure);

            // A credential library must validate actual expiry, issuer, token
            // audience and permissions. Here only empty credentials are denied.
            return token;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // No original exception/inner details: a credential supplier could
            // include the token (or SQL connection string) in its message.
            throw new InvalidOperationException(Failure);
        }
    }
}
