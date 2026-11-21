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

    // #140 / ADR 0105: RED-first independent Npgsql password-provider
    // boundary, even if the caller-supplied Entra token provider is faulty.
    [Theory]
    [InlineData("TOKEN\r\nSECRET-CANARY")]
    [InlineData("TOKEN\u0000SECRET-CANARY")]
    [InlineData("TOKEN\tSECRET-CANARY")]
    [InlineData("TOKEN DEL\u007FSECRET-CANARY")]
    [InlineData("ÉNTRA-SECRET-CANARY")]
    [InlineData("TOKEN\u200DSECRET-CANARY")]
    [InlineData(" TOKEN-SECRET-CANARY")]
    [InlineData("TOKEN-SECRET-CANARY ")]
    public async Task RejectsNonPrintableOrNonAsciiTokenBeforeNpgsqlSeesIt(string malformed)
    {
        var attempts = 0;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await EntraPostgresDataSourceCandidate.RequestTokenAsync(
                (scope, _) =>
                {
                    attempts++;
                    Assert.Equal(EntraPostgresDataSourceCandidate.PostgreSqlEntraScope, scope);
                    return ValueTask.FromResult(malformed);
                }, CancellationToken.None));

        Assert.Equal(1, attempts);
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("SECRET-CANARY", error.ToString());
        Assert.DoesNotContain(malformed, error.ToString());
    }

    [Fact]
    public async Task RejectsOversizedOpaqueTokenWithoutEchoingAnyBearer()
    {
        var oversized = "SYNTHETIC-TOKEN-SECRET-CANARY-" + new string('X', 16001);
        var attempts = 0;
        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            async () => await EntraPostgresDataSourceCandidate.RequestTokenAsync(
                (_, _) =>
                {
                    attempts++;
                    return ValueTask.FromResult(oversized);
                }, CancellationToken.None));

        Assert.Equal(1, attempts);
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("SYNTHETIC-TOKEN-SECRET-CANARY", error.ToString());
    }

    [Fact]
    public async Task ExactlySixteenThousandPrintableTokenCharactersRemainAllowed()
    {
        var boundaryToken = new string('A', 16000);
        var attempts = 0;
        var returned = await EntraPostgresDataSourceCandidate.RequestTokenAsync(
            (scope, _) =>
            {
                attempts++;
                Assert.Equal(EntraPostgresDataSourceCandidate.PostgreSqlEntraScope, scope);
                return ValueTask.FromResult(boundaryToken);
            }, CancellationToken.None);

        Assert.Equal(1, attempts);
        Assert.Equal(boundaryToken, returned);
    }

    [Fact]
    public async Task CancellationDuringCooperativeTokenSupplierCannotForwardToken()
    {
        using var cancelled = new CancellationTokenSource();
        var attempts = 0;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            async () => await EntraPostgresDataSourceCandidate.RequestTokenAsync(
                (scope, _) =>
                {
                    attempts++;
                    Assert.Equal(EntraPostgresDataSourceCandidate.PostgreSqlEntraScope, scope);
                    cancelled.Cancel();
                    // A badly implemented supplier ignores its cancellation,
                    // then successfully returns a bearer. Never pass it to SQL.
                    return ValueTask.FromResult("SYNTHETIC-IGNORED-CANCELLATION");
                }, cancelled.Token));
        Assert.Equal(1, attempts);
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
