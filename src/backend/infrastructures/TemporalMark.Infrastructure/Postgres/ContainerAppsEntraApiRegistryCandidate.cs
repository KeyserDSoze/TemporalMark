using System.Text.RegularExpressions;
using Npgsql;

namespace TemporalMark.Infrastructure.Postgres;

/// <summary>
/// #134 / ADR 0100: optional API-only composition of the previously reviewed
/// #130/#131 Entra Npgsql datasource and ACA local managed identity supplier.
/// Creation is completely offline, never accesses SQL/HTTP or stores tokens.
/// Actual first SQL login + role check is mandatory BEFORE the API listens.
/// </summary>
public sealed class ContainerAppsEntraApiRegistryCandidate : IDisposable
{
    private const string StartupFailure = "Registry PostgreSQL Entra startup denied";
    private readonly ContainerAppsPostgresManagedIdentityCandidate identity;
    private bool disposed;

    public NpgsqlDataSource DataSource { get; }
    public string ExpectedRuntimeLogin { get; }

    private ContainerAppsEntraApiRegistryCandidate(
        ContainerAppsPostgresManagedIdentityCandidate identity,
        NpgsqlDataSource dataSource, string expectedRuntimeLogin)
    {
        this.identity = identity;
        DataSource = dataSource;
        ExpectedRuntimeLogin = expectedRuntimeLogin;
    }

    /// <summary>
    /// Requires a distinct, explicitly approved user-assigned managed identity
    /// and exactly matched PostgreSQL runtime role. Inputs must come from
    /// operator config and ACA-owned process environment, never a request.
    /// </summary>
    public static ContainerAppsEntraApiRegistryCandidate Create(
        string? connectionString,
        string? localIdentityEndpoint,
        string? platformIdentityHeader,
        string? userAssignedClientId,
        string? expectedRuntimeLogin)
    {
        // No Azure, DNS, token or database connection in this method.
        if (string.IsNullOrWhiteSpace(expectedRuntimeLogin) ||
            !Regex.IsMatch(expectedRuntimeLogin,
                @"\A[A-Za-z_][A-Za-z0-9_-]{1,62}\z",
                RegexOptions.CultureInvariant))
            throw new ArgumentException("An approved canonical runtime SQL login is required",
                nameof(expectedRuntimeLogin));

        if (userAssignedClientId is null ||
            !Guid.TryParseExact(userAssignedClientId, "D", out var clientId) ||
            clientId == Guid.Empty ||
            !string.Equals(clientId.ToString("D"), userAssignedClientId,
                StringComparison.Ordinal))
            throw new ArgumentException("An explicit canonical user-assigned identity client GUID is required",
                nameof(userAssignedClientId));

        // Deliberately validate role string against Npgsql's own parsed
        // Username rather than accepting a second unverified SQL principal.
        NpgsqlConnectionStringBuilder parsed;
        try
        {
            parsed = new NpgsqlConnectionStringBuilder(connectionString ?? "");
        }
        catch (Exception)
        {
            // A malicious configuration can include SQL passwords/hostnames.
            throw new ArgumentException("Invalid approved PostgreSQL connection configuration",
                nameof(connectionString));
        }

        if (!string.Equals(parsed.Username, expectedRuntimeLogin, StringComparison.Ordinal))
            throw new ArgumentException("Configured PostgreSQL runtime login mismatch",
                nameof(expectedRuntimeLogin));

        ContainerAppsPostgresManagedIdentityCandidate? identity = null;
        try
        {
            identity = ContainerAppsPostgresManagedIdentityCandidate.Create(
                localIdentityEndpoint ?? "", platformIdentityHeader ?? "", clientId);
            var dataSource = EntraPostgresDataSourceCandidate.Create(
                connectionString ?? "", identity.GetTokenAsync);
            return new ContainerAppsEntraApiRegistryCandidate(
                identity, dataSource, expectedRuntimeLogin);
        }
        catch (Exception)
        {
            identity?.Dispose();
            // Never retain raw transport, platform header or connection string
            // diagnostics, even when the lower-level validation rejects inputs.
            throw new ArgumentException("Invalid approved Entra PostgreSQL runtime configuration");
        }
    }

    /// <summary>
    /// Required only in explicit opt-in API mode; tests real private network,
    /// TLS, Entra SQL authentication and effective non-admin SQL role in an
    /// already-opened session, before binding HTTP. Fail closed for any fault.
    /// </summary>
    public async Task VerifyAtStartupAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            await using var connection = await DataSource.OpenConnectionAsync(cancellationToken);
            await PostgresRuntimePrivilegePreflight.VerifyAsync(
                connection, ExpectedRuntimeLogin, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // No original exception or inner exception: Npgsql can echo a
            // host, role or server-supplied SQL text in underlying errors.
            throw new InvalidOperationException(StartupFailure);
        }
    }

    public void Dispose()
    {
        if (disposed) return;
        disposed = true;
        try
        {
            DataSource.Dispose();
        }
        finally
        {
            identity.Dispose();
        }
    }
}
