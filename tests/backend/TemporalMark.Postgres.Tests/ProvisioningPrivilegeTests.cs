using Npgsql;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>Tests deny-by-default SQL roles, immutable audit insert and proof replay.</summary>
public sealed class ProvisioningPrivilegeTests
{
    private static NpgsqlConnection MigrationOwner() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
        ?? throw new InvalidOperationException("TEMPORALMARK_TEST_DB is required."));
    private static NpgsqlConnection Operator() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_PROVISIONING_TEST_DB")
        ?? throw new InvalidOperationException("TEMPORALMARK_PROVISIONING_TEST_DB is required."));

    [Fact]
    public async Task RuntimeRoleCannotBootstrapOrWriteOrganizationMembership()
    {
        await using var c = MigrationOwner();
        await c.OpenAsync();
        await using var q = new NpgsqlCommand("""
            SELECT has_function_privilege('temporalmark_runtime_group','public.bootstrap_organization(uuid,text,text)','EXECUTE'),
                   has_function_privilege('temporalmark_runtime_group',
                     'public.bootstrap_verified_organization(uuid,text,text,text,text,char(64),char(64))','EXECUTE'),
                   has_table_privilege('temporalmark_runtime_group','public.organization_memberships','INSERT'),
                   has_table_privilege('temporalmark_runtime_group','public.organization_memberships','SELECT'),
                   has_table_privilege('temporalmark_provisioner_group','public.organization_memberships','SELECT')
            """, c);
        await using var reader = await q.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.False(reader.GetBoolean(0));
        Assert.False(reader.GetBoolean(1));
        Assert.False(reader.GetBoolean(2));
        Assert.True(reader.GetBoolean(3));
        Assert.False(reader.GetBoolean(4));
    }

    [Fact]
    public async Task ProvisionerCannotCallLegacyDirectBootstrapEvenWithValidLookingClaims()
    {
        await using var c = Operator();
        await c.OpenAsync();
        await using var old = new NpgsqlCommand(
            "SELECT public.bootstrap_verified_organization(@org,'Forbidden','fabricated-admin'," +
            "'https://issuer.example.test','fabricated-operator',@a::char(64),@b::char(64))", c);
        old.Parameters.AddWithValue("org", Guid.NewGuid());
        old.Parameters.AddWithValue("a", new string('A', 64));
        old.Parameters.AddWithValue("b", new string('B', 64));
        var denied = await Assert.ThrowsAsync<PostgresException>(async () => await old.ExecuteScalarAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denied.SqlState);
    }

    [Fact]
    public async Task DirectTableMutationFailsForProvisionerLogin()
    {
        await using var c = Operator();
        await c.OpenAsync();
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO organizations(id,display_name,is_active) VALUES (@id,'Unauthorized',false)", c);
        cmd.Parameters.AddWithValue("id", Guid.NewGuid());
        var e = await Assert.ThrowsAsync<PostgresException>(async () => await cmd.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, e.SqlState);
    }
}
