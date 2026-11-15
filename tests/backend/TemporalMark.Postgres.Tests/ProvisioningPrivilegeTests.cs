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
    public async Task ProvisionerHasOnlyNarrowVerifiedBootstrapAndProofsAreOneTime()
    {
        var org = Guid.NewGuid();
        await using var c = Operator();
        await c.OpenAsync();
        await using var old = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@org,'Forbidden','fabricated-sub')", c);
        old.Parameters.AddWithValue("org", Guid.NewGuid());
        var denied = await Assert.ThrowsAsync<PostgresException>(async () => await old.ExecuteScalarAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denied.SqlState);

        const string opHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        const string adminHash = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        async Task<Guid> Enroll(Guid id, string operatorTokenHash, string adminTokenHash)
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT public.bootstrap_verified_organization(@id,@name,@admin,@issuer,@operator,
                       @operatorHash::char(64),@adminHash::char(64))
                """, c);
            cmd.Parameters.AddWithValue("id", id);
            cmd.Parameters.AddWithValue("name", "Privileged " + id.ToString("N"));
            cmd.Parameters.AddWithValue("admin", "admin-subject");
            cmd.Parameters.AddWithValue("issuer", "http://localhost:8081/realms/temporalmark");
            cmd.Parameters.AddWithValue("operator", "operator-subject");
            cmd.Parameters.AddWithValue("operatorHash", operatorTokenHash);
            cmd.Parameters.AddWithValue("adminHash", adminTokenHash);
            return Assert.IsType<Guid>(await cmd.ExecuteScalarAsync());
        }

        Assert.Equal(org, await Enroll(org, opHash, adminHash));
        var replay = await Assert.ThrowsAsync<PostgresException>(async () =>
            await Enroll(Guid.NewGuid(), opHash, adminHash));
        Assert.Equal(PostgresErrorCodes.UniqueViolation, replay.SqlState);

        await using var owner = MigrationOwner();
        await owner.OpenAsync();
        await using var audit = new NpgsqlCommand("""
            SELECT first_admin_subject, identity_issuer, provisioner_subject
            FROM public.organization_provisioning_events WHERE organization_id = @org
            """, owner);
        audit.Parameters.AddWithValue("org", org);
        await using var rows = await audit.ExecuteReaderAsync();
        Assert.True(await rows.ReadAsync());
        Assert.Equal("admin-subject", rows.GetString(0));
        Assert.Equal("http://localhost:8081/realms/temporalmark", rows.GetString(1));
        Assert.Equal("operator-subject", rows.GetString(2));
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
