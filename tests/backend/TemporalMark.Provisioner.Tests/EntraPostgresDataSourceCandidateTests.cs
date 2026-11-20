using Npgsql;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// #130 / ADR 0096 RED FIRST. Offline Npgsql candidate test surface only:
/// no Entra account, SQL socket, JWT, remote DNS, fixture secret or API switch.
/// </summary>
public sealed class EntraPostgresDataSourceCandidateTests
{
    private const string Safe =
        "Host=tm-ci-pg.postgres.database.azure.com;Port=5432;Database=temporalmark;" +
        "Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable";

    private static ValueTask<string> FakeToken(string _, CancellationToken __) =>
        ValueTask.FromResult("FAKE-OPAQUE-NOT-A-JWT");

    [Fact]
    public void BuildsOnlyExplicitOptInNoSocketDataSource()
    {
        using var source = EntraPostgresDataSourceCandidate.Create(Safe, FakeToken);
        Assert.NotNull(source);
        Assert.DoesNotContain("FAKE-OPAQUE-NOT-A-JWT", source.ConnectionString);
    }

    [Theory]
    [InlineData("Host=localhost;Port=5432;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=127.0.0.1;Port=5432;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com,evil.example.net;Port=5432;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=evil.postgres.database.azure.com.attacker.test;Port=5432;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.privatelink.postgres.database.azure.com;Port=5432;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Port=6432;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Port=5432;Database=temporalmark;Username=;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Port=5432;Database=;Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Port=5432;Database=temporalmark;Username=tm-api-mi;SSL Mode=Require;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Port=5432;Database=temporalmark;Username=tm-api-mi;SSL Mode=Disable;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Port=5432;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Port=5432;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Prefer")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Port=5432;Database=temporalmark;Username=tm-api-mi;Password=SQL-SECRET;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Port=5432;Database=temporalmark;Username=tm-api-mi;Passfile=/tmp/passwords;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Port=5432;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable;Trust Server Certificate=true")]
    public void RejectsUntrustedOrSecretBearingConnectionStrings(string connectionString)
    {
        var error = Assert.Throws<ArgumentException>(() =>
            EntraPostgresDataSourceCandidate.Create(connectionString, FakeToken));
        Assert.DoesNotContain("SQL-SECRET", error.ToString());
        Assert.DoesNotContain("/tmp/passwords", error.ToString());
    }

    [Fact]
    public void RequiresExplicitTokenSupplier()
    {
        Assert.Throws<ArgumentNullException>(() =>
            EntraPostgresDataSourceCandidate.Create(Safe, null!));
    }

    [Fact]
    public async Task RequestsOnlyPinnedPostgresEntraScope()
    {
        string? observedScope = null;
        using var cancellation = new CancellationTokenSource();
        var result = await EntraPostgresDataSourceCandidate.RequestTokenAsync(
            (scope, _) =>
            {
                observedScope = scope;
                return ValueTask.FromResult("SYNTHETIC-NON-AZURE-TOKEN");
            }, cancellation.Token);
        Assert.Equal("https://ossrdbms-aad.database.windows.net/.default", observedScope);
        Assert.Equal("SYNTHETIC-NON-AZURE-TOKEN", result);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public async Task MissingTokenFailsClosedWithSafeException(string candidate)
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await EntraPostgresDataSourceCandidate.RequestTokenAsync(
                (_, _) => ValueTask.FromResult(candidate), CancellationToken.None));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain(candidate == "" ? "FAKE" : "SENSITIVE", error.ToString());
    }

    [Fact]
    public async Task SupplierExceptionNeverLeaksBearerThroughMessageOrInnerException()
    {
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await EntraPostgresDataSourceCandidate.RequestTokenAsync(
                (_, _) => throw new InvalidOperationException("JWT-BEARER-SECRET-CANARY"),
                CancellationToken.None));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("JWT-BEARER-SECRET-CANARY", error.ToString());
    }

    [Fact]
    public async Task CallerCancellationIsPreservedWithoutPasswordFallback()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await EntraPostgresDataSourceCandidate.RequestTokenAsync(
                (_, ct) => throw new OperationCanceledException(ct),
                cancelled.Token));
    }

    [Fact]
    public async Task SupplierTokenCannotOverridePinnedScopeOrCallerCancellation()
    {
        string? scope = null;
        await EntraPostgresDataSourceCandidate.RequestTokenAsync(
            (received, ct) =>
            {
                scope = received;
                Assert.False(ct.IsCancellationRequested);
                return ValueTask.FromResult("SYNTHETIC");
            }, CancellationToken.None);
        Assert.Equal("https://ossrdbms-aad.database.windows.net/.default", scope);
    }
}
