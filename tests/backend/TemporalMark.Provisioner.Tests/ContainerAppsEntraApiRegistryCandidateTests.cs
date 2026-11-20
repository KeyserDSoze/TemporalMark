using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// #134 / ADR 0100: RED-first API Entra candidate composition, without Azure
/// account, HTTP requests, SQL socket, token or password. On-prem SQL mode
/// remains owned by Program.cs and is separately source-policy checked.
/// </summary>
public sealed class ContainerAppsEntraApiRegistryCandidateTests
{
    private const string SafeSql =
        "Host=tm-ci-pg.postgres.database.azure.com;Port=5432;" +
        "Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull;" +
        "GSS Encryption Mode=Disable";
    private const string Endpoint = "http://localhost:42356/msi/token";
    private const string Header = "SYNTHETIC-ROTATING-ACA-HEADER-NOT-SECRET";
    private const string Client = "22222222-2222-4222-8222-222222222222";
    private const string Login = "tm-api-mi";

    private static ContainerAppsEntraApiRegistryCandidate Create(
        string? sql = SafeSql, string? endpoint = Endpoint,
        string? header = Header, string? clientId = Client, string? login = Login) =>
        ContainerAppsEntraApiRegistryCandidate.Create(sql, endpoint, header, clientId, login);

    [Fact]
    public void ExplicitApprovedConfigurationBuildsDataSourceWithoutAnyNetworkOrToken()
    {
        // A successful build on an offline GitHub runner proves no token
        // retrieval or PostgreSQL socket is required merely to configure DI.
        using var candidate = Create();
        Assert.NotNull(candidate.DataSource);
        Assert.Equal(Login, candidate.ExpectedRuntimeLogin);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("not-a-guid-SQL-PASSWORD-CANARY")]
    [InlineData("22222222222242228222222222222222")]
    public void RefusesMissingZeroOrNoncanonicalUserAssignedIdentityClientId(string? client)
    {
        var error = Assert.Throws<ArgumentException>(() => Create(clientId: client));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("SQL-PASSWORD-CANARY", error.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("tm-api-other")]
    [InlineData("temporalmark_api")]
    [InlineData("tm-api-mi;Password=SQL-PASSWORD-CANARY")]
    public void RequiresExactOperatorApprovedDbLoginMatchingNpgsqlUsername(string? login)
    {
        var error = Assert.Throws<ArgumentException>(() => Create(login: login));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("SQL-PASSWORD-CANARY", error.ToString());
        Assert.DoesNotContain("tm-api-other", error.ToString());
    }

    [Theory]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Database=temporalmark;Username=tm-api-mi;Password=SQL-PASSWORD-CANARY;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Database=temporalmark;Username=tm-api-mi;Passfile=/tmp/SECRET-CANARY;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Database=temporalmark;Username=tm-api-mi;SSL Mode=Require;GSS Encryption Mode=Disable")]
    [InlineData("Host=tm-ci-pg.postgres.database.azure.com;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull")]
    [InlineData("Host=evil.example.org;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("Host=localhost;Database=temporalmark;Username=tm-api-mi;SSL Mode=VerifyFull;GSS Encryption Mode=Disable")]
    [InlineData("")]
    public void RefusesSqlPasswordPassfileTlsDowngradeOrUntrustedHost(string sql)
    {
        var error = Assert.Throws<ArgumentException>(() => Create(sql: sql));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("SQL-PASSWORD-CANARY", error.ToString());
        Assert.DoesNotContain("SECRET-CANARY", error.ToString());
        Assert.DoesNotContain("evil.example.org", error.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("http://169.254.169.254:42356/msi/token")]
    [InlineData("https://localhost:42356/msi/token")]
    [InlineData("http://public.example.net:42356/msi/token")]
    [InlineData("http://localhost:42356/msi/token?secret=SECRET-CANARY")]
    public void RefusesMissingOrUntrustedIdentityEndpoint(string? endpoint)
    {
        var error = Assert.Throws<ArgumentException>(() => Create(endpoint: endpoint));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("SECRET-CANARY", error.ToString());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("CONFIDENTIAL-HEADER\r\nX-Evil: SECRET-CANARY")]
    public void RefusesAbsentOrInjectedPlatformIdentityHeader(string? header)
    {
        var error = Assert.Throws<ArgumentException>(() => Create(header: header));
        Assert.Null(error.InnerException);
        Assert.DoesNotContain("SECRET-CANARY", error.ToString());
    }

    [Fact]
    public void MissingConnectionStringFailsClosedWithoutReadingAmbientNpgsqlCredentials()
    {
        var error = Assert.Throws<ArgumentException>(() => Create(sql: null));
        Assert.Null(error.InnerException);
    }

    [Fact]
    public async Task CancelledStartupCannotTriggerAzureOrSqlFallback()
    {
        using var candidate = Create();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => candidate.VerifyAtStartupAsync(cts.Token));
    }
}
