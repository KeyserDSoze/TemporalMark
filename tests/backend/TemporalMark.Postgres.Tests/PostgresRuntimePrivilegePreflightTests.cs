using Npgsql;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// ADR 0099 / #133, real PostgreSQL 17 first: prove a runtime login can be
/// distinguished from owner, privileged operator and independent approver.
/// Never execute CREATE/GRANT/REVOKE/SET ROLE or mutate data in this probe.
/// </summary>
public sealed class PostgresRuntimePrivilegePreflightTests
{
    private static NpgsqlConnection Connection(string key) => new(
        Environment.GetEnvironmentVariable(key)
            ?? throw new InvalidOperationException("Required local PostgreSQL CI fixture is unavailable"));

    private static NpgsqlConnection Runtime() =>
        Connection("TEMPORALMARK_RUNTIME_TEST_DB");

    private static NpgsqlConnection Owner() =>
        Connection("TEMPORALMARK_TEST_DB");

    private static NpgsqlConnection Provisioner() =>
        Connection("TEMPORALMARK_PROVISIONING_TEST_DB");

    private static NpgsqlConnection Approver() =>
        Connection("TEMPORALMARK_APPROVER_TEST_DB");

    private static async Task<long> MigrationCountAsync(NpgsqlConnection connection)
    {
        await using var cmd = new NpgsqlCommand("SELECT count(*) FROM public.schema_migrations", connection);
        return Assert.IsType<long>(await cmd.ExecuteScalarAsync());
    }

    [Fact]
    public async Task LocalRuntimeWithExpectedReadOnlyAclCanPassWithoutModifyingMigrations()
    {
        // The ordinary runtime login must NOT be granted access to the
        // migration-owner ledger merely to test read-only behavior.
        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));
        await using var c = Runtime();
        await c.OpenAsync();
        await PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark_api", CancellationToken.None);
        Assert.Equal(20L, await MigrationCountAsync(owner));
    }

    [Fact]
    public async Task DatabaseOwnerOrSuperuserIsRejectedEvenIfConfiguredAsExpectedLogin()
    {
        await using var c = Owner();
        await c.OpenAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark", CancellationToken.None));
        Assert.Null(ex.InnerException);
        Assert.DoesNotContain("Password=", ex.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(20L, await MigrationCountAsync(c));
    }

    [Fact]
    public async Task ProvisionerLoginIsRejectedDespiteValidSqlLogin()
    {
        await using var c = Provisioner();
        await c.OpenAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark_provisioner",
                CancellationToken.None));
        Assert.Null(ex.InnerException);
        Assert.DoesNotContain("local-provisioner-only", ex.ToString());
    }

    [Fact]
    public async Task IndependentApproverLoginIsRejectedDespiteValidSqlLogin()
    {
        await using var c = Approver();
        await c.OpenAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark_approver",
                CancellationToken.None));
        Assert.Null(ex.InnerException);
        Assert.DoesNotContain("local-approver-only", ex.ToString());
    }

    [Theory]
    [InlineData("temporalmark_provisioner")]
    [InlineData("temporalmark_approver")]
    [InlineData("temporalmark")]
    public async Task RuntimeSessionCannotClaimAnotherExpectedDbLogin(string expectedLogin)
    {
        await using var c = Runtime();
        await c.OpenAsync();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, expectedLogin, CancellationToken.None));
        Assert.Null(ex.InnerException);
        Assert.DoesNotContain(expectedLogin, ex.ToString());
    }

    [Fact]
    public async Task ClosedConnectionCannotBeOpenedByThePreflight()
    {
        await using var c = Runtime();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark_api",
                CancellationToken.None));
        Assert.Null(ex.InnerException);
        Assert.Equal(System.Data.ConnectionState.Closed, c.State);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("a;DROP ROLE")]
    [InlineData("a\nsecret")]
    public async Task RejectsUnapprovedPrincipalSyntaxWithoutOpeningAConnection(string login)
    {
        await using var c = Runtime();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, login, CancellationToken.None));
        Assert.Equal(System.Data.ConnectionState.Closed, c.State);
    }

    [Fact]
    public async Task ExplicitCancellationIsPreservedWithoutRunningAnySql()
    {
        await using var c = Runtime();
        await c.OpenAsync();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(c, "temporalmark_api", cancelled.Token));
        await using var owner = Owner();
        await owner.OpenAsync();
        Assert.Equal(20L, await MigrationCountAsync(owner));
    }

    [Fact]
    public async Task NullConnectionDoesNotAttemptToDiscoverAnyAmbientCredentials()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            PostgresRuntimePrivilegePreflight.VerifyAsync(null!, "temporalmark_api",
                CancellationToken.None));
    }
}
