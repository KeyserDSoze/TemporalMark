using System.Data;
using Npgsql;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// Integration tests against real PostgreSQL 17, run after migrations in Docker CI.
/// They do not mutate the seeded demo tenant; every test creates unique organizations.
/// </summary>
public sealed class TenantIntegrityTests
{
    private static readonly Guid DemoOrganization = Guid.Parse("11111111-1111-1111-1111-111111111111");

    private static NpgsqlConnection Connection() =>
        new(Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("TEMPORALMARK_TEST_DB must be configured for PostgreSQL integration tests."));

    private static async Task<Guid> BootstrapAsync(string actor = "oidc-verified-subject")
    {
        await using var conn = Connection();
        await conn.OpenAsync();
        var org = Guid.NewGuid();
        await using var cmd = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, @actor)", conn);
        cmd.Parameters.AddWithValue("id", org);
        cmd.Parameters.AddWithValue("name", "Integration " + org.ToString("N"));
        cmd.Parameters.AddWithValue("actor", actor);
        Assert.Equal(org, Assert.IsType<Guid>(await cmd.ExecuteScalarAsync()));
        return org;
    }

    private static async Task<long> ActiveAdminCountAsync(Guid organization)
    {
        await using var conn = Connection();
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT count(*) FROM organization_memberships
            WHERE organization_id = @org AND role = 'tenant_admin' AND is_active
            """, conn);
        cmd.Parameters.AddWithValue("org", organization);
        return Assert.IsType<long>(await cmd.ExecuteScalarAsync());
    }

    [Fact]
    public async Task ExistingDemoSeedIsPreservedAndMigrationsAreRecorded()
    {
        Assert.Equal(1L, await ActiveAdminCountAsync(DemoOrganization));
        await using var conn = Connection();
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("SELECT count(*) FROM public.schema_migrations", conn);
        Assert.Equal(15L, Assert.IsType<long>(await cmd.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task ActiveOrganizationWithoutAdminIsRejectedAtCommitEvenViaDirectSql()
    {
        await using var conn = Connection();
        await conn.OpenAsync();
        var org = Guid.NewGuid();
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO organizations(id, display_name) VALUES (@id, 'No admin')", conn);
        cmd.Parameters.AddWithValue("id", org);
        var failure = await Assert.ThrowsAsync<PostgresException>(async () => await cmd.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, failure.SqlState);
    }

    [Fact]
    public async Task BootstrapCreatesAnActiveOrganizationAndItsFirstAdminInOneCommit()
    {
        var org = await BootstrapAsync();
        Assert.Equal(1L, await ActiveAdminCountAsync(org));
        await using var conn = Connection();
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT is_active FROM organizations WHERE id = @org
            """, conn);
        cmd.Parameters.AddWithValue("org", org);
        Assert.True(Assert.IsType<bool>(await cmd.ExecuteScalarAsync()));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("bad\nsubject")]
    public async Task BootstrapRejectsMissingOrUnsafeSubjectWithoutCreatingAnOrganization(string actor)
    {
        await using var conn = Connection();
        await conn.OpenAsync();
        var org = Guid.NewGuid();
        await using var cmd = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, 'Rejected Organization', @actor)", conn);
        cmd.Parameters.AddWithValue("id", org);
        cmd.Parameters.AddWithValue("actor", actor);
        var failure = await Assert.ThrowsAsync<PostgresException>(async () => await cmd.ExecuteScalarAsync());
        Assert.Equal(PostgresErrorCodes.InvalidParameterValue, failure.SqlState);
        await using var check = new NpgsqlCommand("SELECT count(*) FROM organizations WHERE id = @id", conn);
        check.Parameters.AddWithValue("id", org);
        Assert.Equal(0L, Assert.IsType<long>(await check.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task ReactivationRequiresFirstAdmin()
    {
        await using var conn = Connection();
        await conn.OpenAsync();
        var org = Guid.NewGuid();
        await using (var insert = new NpgsqlCommand(
            "INSERT INTO organizations(id, display_name, is_active) VALUES (@id, 'Inactive', false)", conn))
        {
            insert.Parameters.AddWithValue("id", org);
            await insert.ExecuteNonQueryAsync();
        }
        await using var activate = new NpgsqlCommand(
            "UPDATE organizations SET is_active = true WHERE id = @id", conn);
        activate.Parameters.AddWithValue("id", org);
        var error = await Assert.ThrowsAsync<PostgresException>(async () => await activate.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
    }

    [Fact]
    public async Task LastAdminCannotBeDeletedByDirectSql()
    {
        var org = await BootstrapAsync();
        await using var conn = Connection();
        await conn.OpenAsync();
        await using var remove = new NpgsqlCommand(
            "DELETE FROM organization_memberships WHERE organization_id=@org", conn);
        remove.Parameters.AddWithValue("org", org);
        var error = await Assert.ThrowsAsync<PostgresException>(async () => await remove.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
        Assert.Equal(1L, await ActiveAdminCountAsync(org));
    }

    [Fact]
    public async Task ReassigningOnlyAdminToAnotherOrganizationFailsClosed()
    {
        var from = await BootstrapAsync("first-admin");
        var to = await BootstrapAsync("second-admin");
        await using var conn = Connection();
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            UPDATE organization_memberships SET organization_id = @to
            WHERE organization_id = @from AND subject_id = 'first-admin'
            """, conn);
        cmd.Parameters.AddWithValue("from", from);
        cmd.Parameters.AddWithValue("to", to);
        var error = await Assert.ThrowsAsync<PostgresException>(async () => await cmd.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
        Assert.Equal(1L, await ActiveAdminCountAsync(from));
    }

    [Theory]
    [InlineData("UPDATE")]
    [InlineData("DELETE")]
    public async Task TwoConcurrentAdminRemovalsCannotLeaveAnActiveOrganizationWithZeroAdmins(string mutation)
    {
        var org = await BootstrapAsync("admin-a");
        await using (var setup = Connection())
        {
            await setup.OpenAsync();
            await using var add = new NpgsqlCommand("""
                INSERT INTO organization_memberships(organization_id,subject_id,role,is_active)
                VALUES (@org,'admin-b','tenant_admin',true)
                """, setup);
            add.Parameters.AddWithValue("org", org);
            await add.ExecuteNonQueryAsync();
        }

        await using var first = Connection();
        await using var second = Connection();
        await first.OpenAsync();
        await second.OpenAsync();
        await using var tx1 = await first.BeginTransactionAsync(IsolationLevel.ReadCommitted);
        await using var tx2 = await second.BeginTransactionAsync(IsolationLevel.ReadCommitted);
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var sql1 = mutation == "DELETE" ?
            "DELETE FROM organization_memberships WHERE organization_id=@org AND subject_id='admin-a'" :
            "UPDATE organization_memberships SET role='tenant_member' WHERE organization_id=@org AND subject_id='admin-a'";
        var sql2 = mutation == "DELETE" ?
            "DELETE FROM organization_memberships WHERE organization_id=@org AND subject_id='admin-b'" :
            "UPDATE organization_memberships SET is_active=false WHERE organization_id=@org AND subject_id='admin-b'";
        await using var cmd1 = new NpgsqlCommand(sql1, first, tx1);
        cmd1.Parameters.AddWithValue("org", org);
        await using var cmd2 = new NpgsqlCommand(sql2, second, tx2);
        cmd2.Parameters.AddWithValue("org", org);

        Assert.Equal(1, await cmd1.ExecuteNonQueryAsync(timeout.Token));
        var blockedChange = cmd2.ExecuteNonQueryAsync(timeout.Token);
        // Competing mutation is intentionally submitted while tx1 owns the parent-row lock.
        await Task.Delay(200, timeout.Token);
        Assert.False(blockedChange.IsCompleted);
        await tx1.CommitAsync(timeout.Token);
        try
        {
            await blockedChange;
            var failure = await Assert.ThrowsAsync<PostgresException>(
                async () => await tx2.CommitAsync(timeout.Token));
            Assert.Equal(PostgresErrorCodes.CheckViolation, failure.SqlState);
        }
        catch (PostgresException failure)
        {
            Assert.True(failure.SqlState == PostgresErrorCodes.CheckViolation ||
                        failure.SqlState == PostgresErrorCodes.SerializationFailure);
        }

        Assert.Equal(1L, await ActiveAdminCountAsync(org));
    }
}
