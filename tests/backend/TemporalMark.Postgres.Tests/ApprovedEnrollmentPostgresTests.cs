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
                'public.approve_enrollment(uuid,text,text,text,text,text,char(64),text,text,bigint)','EXECUTE'),
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
        Assert.False(r.GetBoolean(2));
        Assert.True(r.GetBoolean(3));
        Assert.False(r.GetBoolean(4));
        Assert.False(r.GetBoolean(5));
        Assert.False(r.GetBoolean(6));
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
                    @reviewer,@proof::char(64),'OIDC_ACR_ASSERTED',
                    'urn:temporalmark:loa:2',@authTime)
                """, reviewer);
            cmd.Parameters.AddWithValue("id", id);
            cmd.Parameters.AddWithValue("name", expectedName);
            cmd.Parameters.AddWithValue("issuer", issuer);
            cmd.Parameters.AddWithValue("operator", operatorSubject);
            cmd.Parameters.AddWithValue("admin", adminSubject);
            cmd.Parameters.AddWithValue("reviewer", approvedBy);
            cmd.Parameters.AddWithValue("proof", new string('C', 64));
            cmd.Parameters.AddWithValue("authTime", DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 10);
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
            SELECT e.approval_request_id,e.approver_subject,r.consumed_utc IS NOT NULL,
                r.approver_assurance_kind,r.approver_authentication_acr,
                r.approver_authentication_utc IS NOT NULL,r.approval_policy_id
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
        Assert.Equal("OIDC_ACR_ASSERTED",reader.GetString(3));
        Assert.Equal("urn:temporalmark:loa:2",reader.GetString(4));
        Assert.True(reader.GetBoolean(5));
        Assert.Equal("pinned-oidc-acr-v1",reader.GetString(6));
    }

    [Fact]
    public async Task CompetingCompletionsConsumeApprovalExactlyOnce()
    {
        var id = Guid.NewGuid();
        var name = "Concurrent " + id.ToString("N");
        var unique = id.ToString("N").ToUpperInvariant();
        var requestOperator = unique + new string('A', 32);
        var requestAdmin = unique + new string('B', 32);
        var approvalProof = unique + new string('C', 32);
        var finalOperator = unique + new string('D', 32);
        var finalAdmin = unique + new string('E', 32);

        await using (var op = Operator())
        {
            await op.OpenAsync();
            await using var request = new NpgsqlCommand("""
                SELECT public.request_enrollment(@id,@name,'https://issuer.example.test',
                    'op-sub','admin-sub',@a::char(64),@b::char(64))
                """, op);
            request.Parameters.AddWithValue("id", id);
            request.Parameters.AddWithValue("name", name);
            request.Parameters.AddWithValue("a", requestOperator);
            request.Parameters.AddWithValue("b", requestAdmin);
            Assert.Equal(id, Assert.IsType<Guid>(await request.ExecuteScalarAsync()));
        }
        await using (var approver = Approver())
        {
            await approver.OpenAsync();
            await using var approve = new NpgsqlCommand("""
                SELECT public.approve_enrollment(@id,@name,'https://issuer.example.test',
                    'op-sub','admin-sub','different-approver',@hash::char(64),
                    'OIDC_ACR_ASSERTED','urn:temporalmark:loa:2',@authTime)
                """, approver);
            approve.Parameters.AddWithValue("id", id);
            approve.Parameters.AddWithValue("name", name);
            approve.Parameters.AddWithValue("hash", approvalProof);
            approve.Parameters.AddWithValue("authTime", DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 10);
            Assert.Equal(id, Assert.IsType<Guid>(await approve.ExecuteScalarAsync()));
        }

        async Task<(bool Success, string? Failure)> CompeteAsync()
        {
            await using var op = Operator();
            await op.OpenAsync();
            await using var complete = new NpgsqlCommand("""
                SELECT public.complete_enrollment(@id,@name,'https://issuer.example.test',
                    'op-sub','admin-sub',@a::char(64),@b::char(64))
                """, op);
            complete.Parameters.AddWithValue("id", id);
            complete.Parameters.AddWithValue("name", name);
            complete.Parameters.AddWithValue("a", finalOperator);
            complete.Parameters.AddWithValue("b", finalAdmin);
            try
            {
                return (Assert.IsType<Guid>(await complete.ExecuteScalarAsync()) == id, null);
            }
            catch (PostgresException e)
            {
                return (false, e.SqlState);
            }
        }

        var results = await Task.WhenAll(CompeteAsync(), CompeteAsync());
        Assert.Single(results, x => x.Success);
        Assert.Single(results, x => !x.Success && x.Failure == PostgresErrorCodes.CheckViolation);

        await using var owner = Owner();
        await owner.OpenAsync();
        await using var check = new NpgsqlCommand("""
            SELECT
             (SELECT count(*) FROM public.organizations WHERE id=@id),
             (SELECT count(*) FROM public.organization_memberships WHERE organization_id=@id
                 AND role='tenant_admin' AND is_active),
             (SELECT count(*) FROM public.organization_provisioning_events WHERE organization_id=@id)
            """, owner);
        check.Parameters.AddWithValue("id", id);
        await using var reader = await check.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(1L, reader.GetInt64(0));
        Assert.Equal(1L, reader.GetInt64(1));
        Assert.Equal(1L, reader.GetInt64(2));
    }

    [Fact]
    public async Task LegacyApprovalFunctionCannotBeInvokedByRestrictedApproverLogin()
    {
        await using var reviewer = Approver();
        await reviewer.OpenAsync();
        await using var legacy = new NpgsqlCommand("""
            SELECT public.approve_enrollment(@id,'Legacy','https://issuer.example.test',
                'operator','first-admin','reviewer',@hash::char(64))
            """,reviewer);
        legacy.Parameters.AddWithValue("id",Guid.NewGuid());
        legacy.Parameters.AddWithValue("hash",new string('E',64));
        var denial=await Assert.ThrowsAsync<PostgresException>(
            async ()=>await legacy.ExecuteScalarAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege,denial.SqlState);
    }

    [Theory]
    [InlineData("https://external-idp.example.test","DISPOSABLE_PASSWORD_ONLY",null,false)]
    [InlineData("https://external-idp.example.test","OIDC_ACR_ASSERTED",null,false)]
    [InlineData("https://external-idp.example.test","OIDC_ACR_ASSERTED","pwd",false)]
    [InlineData("https://external-idp.example.test","OIDC_ACR_ASSERTED","urn:temporalmark:loa:2",true)]
    public async Task ApprovalRequiresPolicyProvenanceNotArbitraryFixtureAssertion(
        string issuer,string kind,string? context,bool expectedSuccess)
    {
        var id=Guid.NewGuid();
        var unique=id.ToString("N").ToUpperInvariant();
        await using var op=Operator();
        await op.OpenAsync();
        await using(var request=new NpgsqlCommand("""
            SELECT public.request_enrollment(@id,'Provenance',@issuer,
                 'operator','tenant-admin',@operatorProof::char(64),@adminProof::char(64))
            """,op))
        {
            request.Parameters.AddWithValue("id",id);
            request.Parameters.AddWithValue("issuer",issuer);
            request.Parameters.AddWithValue("operatorProof",unique+new string('1',32));
            request.Parameters.AddWithValue("adminProof",unique+new string('2',32));
            Assert.Equal(id,Assert.IsType<Guid>(await request.ExecuteScalarAsync()));
        }
        await using var reviewer=Approver();
        await reviewer.OpenAsync();
        await using var approval=new NpgsqlCommand("""
            SELECT public.approve_enrollment(@id,'Provenance',@issuer,
                'operator','tenant-admin','reviewer',@hash::char(64),
                @kind,@context,@authTime)
            """,reviewer);
        approval.Parameters.AddWithValue("id",id);
        approval.Parameters.AddWithValue("issuer",issuer);
        approval.Parameters.AddWithValue("hash",unique+new string('3',32));
        approval.Parameters.AddWithValue("kind",kind);
        approval.Parameters.AddWithValue("context", (object?)context ?? DBNull.Value);
        approval.Parameters.AddWithValue("authTime",expectedSuccess
            ? (object)(DateTimeOffset.UtcNow.ToUnixTimeSeconds()-10) : DBNull.Value);
        if(expectedSuccess)
            Assert.Equal(id,Assert.IsType<Guid>(await approval.ExecuteScalarAsync()));
        else
            await Assert.ThrowsAsync<PostgresException>(
                async()=>await approval.ExecuteScalarAsync());
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
            UPDATE public.organization_enrollment_requests
            SET requested_utc=clock_timestamp()-interval '10 minutes',
                expires_utc=clock_timestamp()-interval '6 minutes'
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
                'operator-sub','admin-sub','reviewer-sub',@hash::char(64),
                    'OIDC_ACR_ASSERTED','urn:temporalmark:loa:2',@authTime)
            """,approver);
        approval.Parameters.AddWithValue("id",id);
        approval.Parameters.AddWithValue("hash",new string('1',64));
        approval.Parameters.AddWithValue("authTime",DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 10);
        var error=await Assert.ThrowsAsync<PostgresException>(async()=>await approval.ExecuteScalarAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation,error.SqlState);
    }
}
