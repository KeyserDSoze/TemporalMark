using Npgsql;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>Atomic approved enrollment, proof replay, expiry and role isolation in PostgreSQL.</summary>
public sealed class ApprovedEnrollmentPostgresTests
{
    private static NpgsqlConnection Owner() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_TEST_DB missing"));
    private static NpgsqlConnection Operator() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_PROVISIONING_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_PROVISIONING_TEST_DB missing"));
    private static NpgsqlConnection Approver() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_APPROVER_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_APPROVER_TEST_DB missing"));

    [Fact]
    public async Task DistinctSqlRolesCannotBypassApproval()
    {
        await using var db = Owner();
        await db.OpenAsync();
        await using var q = new NpgsqlCommand("""
            SELECT has_function_privilege('temporalmark_provisioner_group',
                'public.bootstrap_verified_organization(uuid,text,text,text,text,char(64),char(64))','EXECUTE'),
              has_function_privilege('temporalmark_provisioner_group',
                'public.approve_enrollment(uuid,text,text,text,text,text,char(64))','EXECUTE'),
              has_function_privilege('temporalmark_approver_group',
                'public.approve_enrollment(uuid,text,text,text,text,text,char(64))','EXECUTE'),
              has_function_privilege('temporalmark_approver_group',
                'public.complete_enrollment(uuid,text,text,text,text,char(64),char(64))','EXECUTE'),
              has_table_privilege('temporalmark_provisioner_group',
                'public.organization_enrollment_requests','UPDATE'),
              has_table_privilege('temporalmark_approver_group',
                'public.organization_enrollment_requests','SELECT')
            """, db);
        await using var r = await q.ExecuteReaderAsync();
        Assert.True(await r.ReadAsync());
        Assert.False(r.GetBoolean(0));
        Assert.False(r.GetBoolean(1));
        Assert.True(r.GetBoolean(2));
        Assert.False(r.GetBoolean(3));
        Assert.False(r.GetBoolean(4));
        Assert.False(r.GetBoolean(5));
    }

    [Fact]
    public async Task CanOnlyCompleteApprovedMatchingRequestOnce()
    {
        var id = Guid.NewGuid();
        var name = "Approved " + id.ToString("N");
        const string issuer = "https://trusted-idp.example.test";
        await using var op = Operator();
        await using var reviewer = Approver();
        await op.OpenAsync();
        await reviewer.OpenAsync();

        async Task<Guid> Request()
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT public.request_enrollment(@id,@name,@issuer,'operator-sub','admin-sub',
                  @opProof::char(64),@adminProof::char(64))
                """, op);
            cmd.Parameters.AddWithValue("id", id);
            cmd.Parameters.AddWithValue("name", name);
            cmd.Parameters.AddWithValue("issuer", issuer);
            cmd.Parameters.AddWithValue("opProof", new string('A', 64));
            cmd.Parameters.AddWithValue("adminProof", new string('B', 64));
            return Assert.IsType<Guid>(await cmd.ExecuteScalarAsync());
        }

        async Task<Guid> Approve(string expectedName, string adminSubject = "admin-sub",
            string operatorSubject = "operator-sub", string approvedBy = "reviewer-sub")
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT public.approve_enrollment(@id,@name,@issuer,@operator,@admin,
                    @reviewer,@proof::char(64))
                """, reviewer);
            cmd.Parameters.AddWithValue("id", id);
            cmd.Parameters.AddWithValue("name", expectedName);
            cmd.Parameters.AddWithValue("issuer", issuer);
            cmd.Parameters.AddWithValue("operator", operatorSubject);
            cmd.Parameters.AddWithValue("admin", adminSubject);
            cmd.Parameters.AddWithValue("reviewer", approvedBy);
            cmd.Parameters.AddWithValue("proof", new string('C', 64));
            return Assert.IsType<Guid>(await cmd.ExecuteScalarAsync());
        }

        async Task<Guid> Complete(string expectedName, string adminSubject = "admin-sub")
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT public.complete_enrollment(@id,@name,@issuer,'operator-sub',@admin,
                    @opProof::char(64),@adminProof::char(64))
                """, op);
            cmd.Parameters.AddWithValue("id", id);
            cmd.Parameters.AddWithValue("name", expectedName);
            cmd.Parameters.AddWithValue("issuer", issuer);
            cmd.Parameters.AddWithValue("admin", adminSubject);
            cmd.Parameters.AddWithValue("opProof", new string('D', 64));
            cmd.Parameters.AddWithValue("adminProof", new string('E', 64));
            return Assert.IsType<Guid>(await cmd.ExecuteScalarAsync());
        }

        Assert.Equal(id, await Request());
        await Assert.ThrowsAsync<PostgresException>(() => Complete(name));
        await Assert.ThrowsAsync<PostgresException>(() => Approve("Another organization"));
        await Assert.ThrowsAsync<PostgresException>(() => Approve(name, approvedBy: "operator-sub"));
        await Assert.ThrowsAsync<PostgresException>(() => Approve(name, adminSubject: "different-admin"));
        Assert.Equal(id, await Approve(name));
        await Assert.ThrowsAsync<PostgresException>(() => Complete("Changed organization"));
        await Assert.ThrowsAsync<PostgresException>(() => Complete(name, "changed-admin"));
        Assert.Equal(id, await Complete(name));
        var replay = await Assert.ThrowsAsync<PostgresException>(() => Complete(name));
        Assert.Equal(PostgresErrorCodes.CheckViolation, replay.SqlState);

        await using var owner = Owner();
        await owner.OpenAsync();
        await using var q = new NpgsqlCommand("""
            SELECT e.approval_request_id,e.approver_subject,r.consumed_utc IS NOT NULL
            FROM public.organization_provisioning_events e
            JOIN public.organization_enrollment_requests r ON r.id=e.approval_request_id
            WHERE e.organization_id=@id
            """, owner);
        q.Parameters.AddWithValue("id", id);
        await using var reader = await q.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(id, reader.GetGuid(0));
        Assert.Equal("reviewer-sub", reader.GetString(1));
        Assert.True(reader.GetBoolean(2));
    }

    [Fact]
    public async Task ExpiredRequestCannotBeApprovedOrCompleted()
    {
        var id=Guid.NewGuid();
        await using var op=Operator();
        await op.OpenAsync();
        await using (var cmd=new NpgsqlCommand("""
            SELECT public.request_enrollment(@id,'Expired Org','https://issuer.test',
                'operator-sub','admin-sub',@a::char(64),@b::char(64))
            """,op))
        {
            cmd.Parameters.AddWithValue("id",id);
            cmd.Parameters.AddWithValue("a",new string('F',64));
            cmd.Parameters.AddWithValue("b",new string('0',64));
            await cmd.ExecuteScalarAsync();
        }
        await using var owner=Owner();
        await owner.OpenAsync();
        await using(var age=new NpgsqlCommand("""
            UPDATE public.organization_enrollment_requests SET expires_utc=clock_timestamp()-interval '1 minute'
            WHERE id=@id
            """,owner))
        {
            age.Parameters.AddWithValue("id",id);
            await age.ExecuteNonQueryAsync();
        }
        await using var approver=Approver();
        await approver.OpenAsync();
        await using var approval=new NpgsqlCommand("""
            SELECT public.approve_enrollment(@id,'Expired Org','https://issuer.test',
                'operator-sub','admin-sub','reviewer-sub',@hash::char(64))
            """,approver);
        approval.Parameters.AddWithValue("id",id);
        approval.Parameters.AddWithValue("hash",new string('1',64));
        var error=await Assert.ThrowsAsync<PostgresException>(async()=>await approval.ExecuteScalarAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation,error.SqlState);
    }
}
