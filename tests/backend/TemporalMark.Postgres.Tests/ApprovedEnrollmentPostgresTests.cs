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
    public async Task ReviewReadsOnlyOriginalPendingUnexpiredScopeWithApproverRole()
    {
        var id = Guid.NewGuid();
        var tag = id.ToString("N").ToUpperInvariant();
        const string issuer = "https://issuer.example.test";
        await using var op = Operator();
        await op.OpenAsync();
        await using (var request = new NpgsqlCommand("""
            SELECT public.request_enrollment(@id,'Original Legal Name',@issuer,
                'operator-sub','first-admin-sub',@operatorProof::char(64),@adminProof::char(64))
            """, op))
        {
            request.Parameters.AddWithValue("id", id);
            request.Parameters.AddWithValue("issuer", issuer);
            request.Parameters.AddWithValue("operatorProof", tag + new string('A', 32));
            request.Parameters.AddWithValue("adminProof", tag + new string('B', 32));
            Assert.Equal(id, Assert.IsType<Guid>(await request.ExecuteScalarAsync()));
        }

        await using var approver = Approver();
        await approver.OpenAsync();
        async Task<(string Name, string Issuer, string Operator, string Admin)> Review(
            string actualIssuer, string subject)
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT request_id,organization_name,identity_issuer,
                       operator_subject,first_admin_subject,expires_utc
                FROM public.read_pending_enrollment(@id,@issuer,@reviewer)
                """, approver);
            cmd.Parameters.AddWithValue("id", id);
            cmd.Parameters.AddWithValue("issuer", actualIssuer);
            cmd.Parameters.AddWithValue("reviewer", subject);
            await using var reader = await cmd.ExecuteReaderAsync();
            if (!await reader.ReadAsync()) throw new UnauthorizedAccessException();
            Assert.Equal(id, reader.GetGuid(0));
            Assert.True(reader.GetFieldValue<DateTimeOffset>(5) > DateTimeOffset.UtcNow);
            return (reader.GetString(1),reader.GetString(2),
                    reader.GetString(3),reader.GetString(4));
        }

        var scope = await Review(issuer, "third-reviewer");
        Assert.Equal("Original Legal Name", scope.Name);
        Assert.Equal(issuer, scope.Issuer);
        Assert.Equal("operator-sub", scope.Operator);
        Assert.Equal("first-admin-sub", scope.Admin);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Review(issuer, "operator-sub"));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Review(issuer, "first-admin-sub"));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Review("https://wrong.example", "third-reviewer"));
        await using var restricted = new NpgsqlCommand("""
            SELECT public.read_pending_enrollment(@id,@issuer,'third-reviewer')
            """, op);
        restricted.Parameters.AddWithValue("id", id);
        restricted.Parameters.AddWithValue("issuer", issuer);
        var denial = await Assert.ThrowsAsync<PostgresException>(
            async () => await restricted.ExecuteScalarAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denial.SqlState);
        await using var direct = new NpgsqlCommand("""
            SELECT organization_name FROM public.organization_enrollment_requests WHERE id=@id
            """, approver);
        direct.Parameters.AddWithValue("id", id);
        var directDenial = await Assert.ThrowsAsync<PostgresException>(
            async () => await direct.ExecuteScalarAsync());
        Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, directDenial.SqlState);
    }

    [Fact]
    public async Task RejectionIsTerminalScopedAndReadOnlyForOtherSqlRoles()
    {
        var id = Guid.NewGuid();
        var tag = id.ToString("N").ToUpperInvariant();
        const string issuer = "https://review.example.test/realm";
        var tokenProof = tag + new string('F', 32);
        var reviewProof = tag + new string('E', 32);
        await using var op = Operator();
        await using var reviewer = Approver();
        await op.OpenAsync();
        await reviewer.OpenAsync();
        await using (var cmd = new NpgsqlCommand("""
            SELECT public.request_enrollment(@id,'Denied Legal Entity',@issuer,
                'requester','intended-admin',@operatorProof::char(64),@adminProof::char(64))
            """, op))
        {
            cmd.Parameters.AddWithValue("id", id);
            cmd.Parameters.AddWithValue("issuer", issuer);
            cmd.Parameters.AddWithValue("operatorProof", tag + new string('A', 32));
            cmd.Parameters.AddWithValue("adminProof", tag + new string('B', 32));
            Assert.Equal(id, Assert.IsType<Guid>(await cmd.ExecuteScalarAsync()));
        }
        async Task<Guid> Reject(string reason, string scopeHash)
        {
            await using var cmd = new NpgsqlCommand("""
                SELECT public.reject_enrollment(@id,'Denied Legal Entity',@issuer,
                    'requester','intended-admin','third-reviewer',
                    @proof::char(64),@review::char(64),@reason)
                """, reviewer);
            cmd.Parameters.AddWithValue("id", id);
            cmd.Parameters.AddWithValue("issuer", issuer);
            cmd.Parameters.AddWithValue("proof", tokenProof);
            cmd.Parameters.AddWithValue("review", scopeHash);
            cmd.Parameters.AddWithValue("reason", reason);
            return Assert.IsType<Guid>(await cmd.ExecuteScalarAsync());
        }
        await Assert.ThrowsAsync<PostgresException>(() => Reject("OTHER CUSTOM TEXT", reviewProof));
        await Assert.ThrowsAsync<PostgresException>(() => Reject("UNVERIFIED_ORGANIZATION", new string('A', 63)));
        Assert.Equal(id, await Reject("UNVERIFIED_ORGANIZATION", reviewProof));
        await Assert.ThrowsAsync<PostgresException>(() => Reject("UNVERIFIED_ORGANIZATION", reviewProof));
        await using (var review = new NpgsqlCommand("""
            SELECT count(*) FROM public.read_pending_enrollment(@id,@issuer,'third-reviewer')
            """, reviewer))
        {
            review.Parameters.AddWithValue("id", id);
            review.Parameters.AddWithValue("issuer", issuer);
            Assert.Equal(0L, Assert.IsType<long>(await review.ExecuteScalarAsync()));
        }
        await using (var approve = new NpgsqlCommand("""
            SELECT public.approve_enrollment(@id,'Denied Legal Entity',@issuer,
                'requester','intended-admin','third-reviewer',@hash::char(64),
                'OIDC_ACR_ASSERTED','urn:temporalmark:loa:2',@authTime)
            """, reviewer))
        {
            approve.Parameters.AddWithValue("id", id);
            approve.Parameters.AddWithValue("issuer", issuer);
            approve.Parameters.AddWithValue("hash", tag + new string('C', 32));
            approve.Parameters.AddWithValue("authTime", DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 10);
            await Assert.ThrowsAsync<PostgresException>(() => approve.ExecuteScalarAsync());
        }
        await using (var complete = new NpgsqlCommand("""
            SELECT public.complete_enrollment(@id,'Denied Legal Entity',@issuer,
                'requester','intended-admin',@hash1::char(64),@hash2::char(64))
            """, op))
        {
            complete.Parameters.AddWithValue("id", id);
            complete.Parameters.AddWithValue("issuer", issuer);
            complete.Parameters.AddWithValue("hash1", tag + new string('D', 32));
            complete.Parameters.AddWithValue("hash2", tag + new string('1', 32));
            await Assert.ThrowsAsync<PostgresException>(() => complete.ExecuteScalarAsync());
        }
        await using var owner = Owner();
        await owner.OpenAsync();
        await using var audit = new NpgsqlCommand("""
            SELECT r.rejected_by_subject,r.rejection_reason_code,
                r.rejected_utc IS NOT NULL,r.rejection_review_sha256,
                (SELECT count(*) FROM public.organizations WHERE id=r.id),
                (SELECT count(*) FROM public.organization_provisioning_events WHERE organization_id=r.id)
            FROM public.organization_enrollment_requests r WHERE r.id=@id
            """, owner);
        audit.Parameters.AddWithValue("id", id);
        await using var reader = await audit.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal("third-reviewer",reader.GetString(0));
        Assert.Equal("UNVERIFIED_ORGANIZATION",reader.GetString(1));
        Assert.True(reader.GetBoolean(2));
        Assert.Equal(reviewProof,reader.GetString(3));
        Assert.Equal(0L,reader.GetInt64(4));
        Assert.Equal(0L,reader.GetInt64(5));
    }

    [Fact]
    public async Task OnlyApproverCanRejectAndOperatorCannotReadRejectionRecords()
    {
        await using var owner = Owner();
        await owner.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT has_function_privilege('temporalmark_approver_group',
                'public.reject_enrollment(uuid,text,text,text,text,text,char(64),char(64),text)','EXECUTE'),
              has_function_privilege('temporalmark_provisioner_group',
                'public.reject_enrollment(uuid,text,text,text,text,text,char(64),char(64),text)','EXECUTE'),
              has_function_privilege('temporalmark_runtime_group',
                'public.reject_enrollment(uuid,text,text,text,text,text,char(64),char(64),text)','EXECUTE'),
              has_table_privilege('temporalmark_approver_group',
                'public.organization_enrollment_requests','UPDATE')
            """, owner);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.True(reader.GetBoolean(0));
        Assert.False(reader.GetBoolean(1));
        Assert.False(reader.GetBoolean(2));
        Assert.False(reader.GetBoolean(3));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task DirectDatabaseWriteCannotCreatePartiallyRecordedRejection(bool missingReviewHash)
    {
        // A PostgreSQL CHECK with NULL expression evaluates UNKNOWN and would
        // incorrectly allow an incomplete rejected row unless every nullable
        // required field is checked using IS NOT NULL.
        var id = Guid.NewGuid();
        var tag = id.ToString("N").ToUpperInvariant();
        await using (var op = Operator())
        {
            await op.OpenAsync();
            await using var request = new NpgsqlCommand("""
                SELECT public.request_enrollment(@id,'Strict rejection','https://idp.example.test',
                    'operator','admin',@operatorHash::char(64),@adminHash::char(64))
                """,op);
            request.Parameters.AddWithValue("id",id);
            request.Parameters.AddWithValue("operatorHash",tag+new string('A',32));
            request.Parameters.AddWithValue("adminHash",tag+new string('B',32));
            Assert.Equal(id,Assert.IsType<Guid>(await request.ExecuteScalarAsync()));
        }
        await using var owner=Owner();
        await owner.OpenAsync();
        await using var tamper=new NpgsqlCommand("""
            UPDATE public.organization_enrollment_requests SET
                rejected_utc=clock_timestamp(),rejected_by_subject='reviewer',
                rejection_proof_sha256=@proof::char(64),
                rejection_review_sha256=@review::char(64),
                rejection_reason_code=@reason
            WHERE id=@id
            """,owner);
        tamper.Parameters.AddWithValue("id",id);
        tamper.Parameters.AddWithValue("proof",tag+new string('C',32));
        tamper.Parameters.AddWithValue("review",missingReviewHash
            ? DBNull.Value : tag+new string('D',32));
        tamper.Parameters.AddWithValue("reason",missingReviewHash
            ? "POLICY_DENIED" : DBNull.Value);
        var error=await Assert.ThrowsAsync<PostgresException>(
            async()=>await tamper.ExecuteNonQueryAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation,error.SqlState);
    }

    [Fact]
    public async Task CompetingApproveAndRejectTransactionsAllowExactlyOneTerminalDecision()
    {
        var id = Guid.NewGuid();
        var digest = id.ToString("N").ToUpperInvariant();
        var name = "Race decision " + id.ToString("N");
        const string issuer = "https://issuer.example.test";
        await using (var op = Operator())
        {
            await op.OpenAsync();
            await using var request = new NpgsqlCommand("""
                SELECT public.request_enrollment(@id,@name,@issuer,'operator','admin',
                    @opHash::char(64),@adminHash::char(64))
                """, op);
            request.Parameters.AddWithValue("id", id);
            request.Parameters.AddWithValue("name", name);
            request.Parameters.AddWithValue("issuer", issuer);
            request.Parameters.AddWithValue("opHash", digest + new string('1', 32));
            request.Parameters.AddWithValue("adminHash", digest + new string('2', 32));
            Assert.Equal(id, Assert.IsType<Guid>(await request.ExecuteScalarAsync()));
        }

        async Task<(bool Success, string? SqlState)> Decide(bool rejection)
        {
            await using var connection = Approver();
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand(rejection ? """
                SELECT public.reject_enrollment(@id,@name,@issuer,'operator','admin',
                    'reviewer',@proof::char(64),@review::char(64),'POLICY_DENIED')
                """ : """
                SELECT public.approve_enrollment(@id,@name,@issuer,'operator','admin',
                    'reviewer',@proof::char(64),
                    'OIDC_ACR_ASSERTED','urn:temporalmark:loa:2',@authTime)
                """, connection);
            command.Parameters.AddWithValue("id", id);
            command.Parameters.AddWithValue("name", name);
            command.Parameters.AddWithValue("issuer", issuer);
            command.Parameters.AddWithValue("proof", digest + new string(rejection ? '4' : '3', 32));
            if (rejection)
                command.Parameters.AddWithValue("review", digest + new string('5', 32));
            else
                command.Parameters.AddWithValue("authTime", DateTimeOffset.UtcNow.ToUnixTimeSeconds() - 10);
            try
            {
                return (Assert.IsType<Guid>(await command.ExecuteScalarAsync()) == id, null);
            }
            catch (PostgresException error)
            {
                return (false, error.SqlState);
            }
        }

        var outcomes = await Task.WhenAll(Decide(false), Decide(true));
        Assert.Single(outcomes, x => x.Success);
        Assert.Single(outcomes, x => !x.Success && x.SqlState == PostgresErrorCodes.CheckViolation);
        await using var owner = Owner();
        await owner.OpenAsync();
        await using var state = new NpgsqlCommand("""
            SELECT (approved_utc IS NOT NULL)::int + (rejected_utc IS NOT NULL)::int,
                (SELECT count(*) FROM public.organization_reviewer_decision_proofs WHERE request_id=@id),
                (SELECT count(*) FROM public.organizations WHERE id=@id),
                (SELECT count(*) FROM public.organization_provisioning_events WHERE organization_id=@id)
            FROM public.organization_enrollment_requests WHERE id=@id
            """, owner);
        state.Parameters.AddWithValue("id", id);
        await using var reader = await state.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(1, reader.GetInt32(0));
        Assert.Equal(1L, reader.GetInt64(1));
        Assert.Equal(0L, reader.GetInt64(2));
        Assert.Equal(0L, reader.GetInt64(3));
    }

    [Fact]
    public async Task ReviewerTokenProofCannotAuthorizeBothApprovalAndRejection()
    {
        const string issuer = "https://issuer.example.test";
        var firstId = Guid.NewGuid();
        var secondId = Guid.NewGuid();
        var firstTag = firstId.ToString("N").ToUpperInvariant();
        var secondTag = secondId.ToString("N").ToUpperInvariant();
        var tokenProof = firstTag + new string('F', 32);

        await using var op = Operator();
        await op.OpenAsync();
        foreach (var (id,tag) in new[] { (firstId,firstTag), (secondId,secondTag) })
        {
            await using var request = new NpgsqlCommand("""
                SELECT public.request_enrollment(@id,'One-use decision proof',@issuer,
                    'operator','admin',@opHash::char(64),@adminHash::char(64))
                """, op);
            request.Parameters.AddWithValue("id", id);
            request.Parameters.AddWithValue("issuer", issuer);
            request.Parameters.AddWithValue("opHash", tag + new string('A', 32));
            request.Parameters.AddWithValue("adminHash", tag + new string('B', 32));
            Assert.Equal(id, Assert.IsType<Guid>(await request.ExecuteScalarAsync()));
        }
        await using var reviewer = Approver();
        await reviewer.OpenAsync();
        await using (var approve = new NpgsqlCommand("""
            SELECT public.approve_enrollment(@id,'One-use decision proof',@issuer,
                'operator','admin','reviewer',@proof::char(64),
                'OIDC_ACR_ASSERTED','urn:temporalmark:loa:2',@authTime)
            """,reviewer))
        {
            approve.Parameters.AddWithValue("id", firstId);
            approve.Parameters.AddWithValue("issuer",issuer);
            approve.Parameters.AddWithValue("proof",tokenProof);
            approve.Parameters.AddWithValue("authTime",DateTimeOffset.UtcNow.ToUnixTimeSeconds()-10);
            Assert.Equal(firstId,Assert.IsType<Guid>(await approve.ExecuteScalarAsync()));
        }
        await using (var reject = new NpgsqlCommand("""
            SELECT public.reject_enrollment(@id,'One-use decision proof',@issuer,
                'operator','admin','reviewer',@proof::char(64),@review::char(64),
                'POLICY_DENIED')
            """,reviewer))
        {
            reject.Parameters.AddWithValue("id",secondId);
            reject.Parameters.AddWithValue("issuer",issuer);
            reject.Parameters.AddWithValue("proof",tokenProof);
            reject.Parameters.AddWithValue("review",secondTag+new string('C',32));
            var denial=await Assert.ThrowsAsync<PostgresException>(
                async()=>await reject.ExecuteScalarAsync());
            Assert.Equal(PostgresErrorCodes.UniqueViolation,denial.SqlState);
        }
        await using var owner=Owner();
        await owner.OpenAsync();
        await using var verify=new NpgsqlCommand("""
            SELECT rejected_utc IS NULL FROM public.organization_enrollment_requests WHERE id=@id
            """,owner);
        verify.Parameters.AddWithValue("id",secondId);
        Assert.True(Assert.IsType<bool>(await verify.ExecuteScalarAsync()));
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
    public async Task HistoricalUnverifiedApprovalCannotBeNewlyConsumed()
    {
        var id = Guid.NewGuid();
        var unique = id.ToString("N").ToUpperInvariant();
        await using (var op = Operator())
        {
            await op.OpenAsync();
            await using var pending = new NpgsqlCommand("""
                SELECT public.request_enrollment(@id,'Historical request',
                    'https://issuer.example.test','historic-operator','historic-admin',
                    @operatorHash::char(64),@adminHash::char(64))
                """, op);
            pending.Parameters.AddWithValue("id", id);
            pending.Parameters.AddWithValue("operatorHash", unique + new string('7', 32));
            pending.Parameters.AddWithValue("adminHash", unique + new string('8', 32));
            Assert.Equal(id, Assert.IsType<Guid>(await pending.ExecuteScalarAsync()));
        }

        // Simulate the explicitly backfilled pre-V008 approval using ONLY
        // the privileged migration-owner connection; the approver SQL role
        // cannot create this historical classification.
        await using (var owner = Owner())
        {
            await owner.OpenAsync();
            await using var old = new NpgsqlCommand("""
                UPDATE public.organization_enrollment_requests
                   SET approved_by_subject='historic-reviewer',
                       approval_proof_sha256=@hash::char(64),
                       approved_utc=clock_timestamp(),
                       approver_assurance_kind='LEGACY_UNVERIFIED',
                       approval_policy_id='legacy-pre-v008'
                 WHERE id=@id
                """, owner);
            old.Parameters.AddWithValue("id", id);
            old.Parameters.AddWithValue("hash", unique + new string('9', 32));
            Assert.Equal(1, await old.ExecuteNonQueryAsync());
        }

        await using var restricted = Operator();
        await restricted.OpenAsync();
        await using var complete = new NpgsqlCommand("""
            SELECT public.complete_enrollment(@id,'Historical request',
                'https://issuer.example.test','historic-operator','historic-admin',
                @operatorProof::char(64),@adminProof::char(64))
            """, restricted);
        complete.Parameters.AddWithValue("id", id);
        complete.Parameters.AddWithValue("operatorProof", unique + new string('A', 32));
        complete.Parameters.AddWithValue("adminProof", unique + new string('B', 32));
        var denial = await Assert.ThrowsAsync<PostgresException>(
            async () => await complete.ExecuteScalarAsync());
        Assert.Equal(PostgresErrorCodes.CheckViolation, denial.SqlState);
        await using var ownerCheck = Owner();
        await ownerCheck.OpenAsync();
        await using var verify = new NpgsqlCommand("""
            SELECT
                (SELECT count(*) FROM public.organizations WHERE id=@id),
                (SELECT count(*) FROM public.organization_provisioning_events WHERE organization_id=@id),
                (SELECT consumed_utc IS NULL FROM public.organization_enrollment_requests WHERE id=@id)
            """, ownerCheck);
        verify.Parameters.AddWithValue("id", id);
        await using var reader = await verify.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(0L, reader.GetInt64(0));
        Assert.Equal(0L, reader.GetInt64(1));
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
