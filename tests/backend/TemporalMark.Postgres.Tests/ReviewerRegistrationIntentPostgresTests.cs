using Npgsql;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// Registrar-only enrollment INTENT (not trusted credential registration).
/// These tests MUST fail before V013: no WebAuthn key or decision may be
/// trusted based on a generated challenge or an arbitrary SQL subject string.
/// </summary>
public sealed class ReviewerRegistrationIntentPostgresTests
{
    private static NpgsqlConnection Owner() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_TEST_DB missing"));
    private static NpgsqlConnection Approver() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_APPROVER_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_APPROVER_TEST_DB missing"));
    private static NpgsqlConnection Operator() => new(
        Environment.GetEnvironmentVariable("TEMPORALMARK_PROVISIONING_TEST_DB") ??
        throw new InvalidOperationException("TEMPORALMARK_PROVISIONING_TEST_DB missing"));

    private static (string Issuer, string Rp, string Origin, string Change) Policy()
    {
        var suffix = Guid.NewGuid().ToString("N");
        var rp = "review-" + suffix + ".example.org";
        return ("https://identity.example.org/realms/" + suffix,
            rp, "https://" + rp, "CAB-" + suffix);
    }

    private static async Task PinPolicy(NpgsqlConnection owner,
        (string Issuer, string Rp, string Origin, string Change) policy)
    {
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO public.reviewer_registration_rp_policies
                (identity_issuer,rp_id,trusted_origin,change_reference)
            VALUES (@issuer,@rp,@origin,@change)
            """, owner);
        cmd.Parameters.AddWithValue("issuer", policy.Issuer);
        cmd.Parameters.AddWithValue("rp", policy.Rp);
        cmd.Parameters.AddWithValue("origin", policy.Origin);
        cmd.Parameters.AddWithValue("change", policy.Change);
        Assert.Equal(1, await cmd.ExecuteNonQueryAsync());
    }

    private static async Task<(Guid Id, string Hex, DateTimeOffset Issued, DateTimeOffset Expires)>
        Issue(NpgsqlConnection db, string issuer, string rp, string origin,
            string reviewer = "reviewer-sub", string registrar = "independent-registrar-sub")
    {
        await using var cmd = new NpgsqlCommand("""
            SELECT intent_id,challenge_hex,issued_utc,expires_utc
            FROM public.issue_reviewer_registration_intent(
                @issuer,@reviewer,@registrar,@rp,@origin)
            """, db);
        cmd.Parameters.AddWithValue("issuer", issuer);
        cmd.Parameters.AddWithValue("reviewer", reviewer);
        cmd.Parameters.AddWithValue("registrar", registrar);
        cmd.Parameters.AddWithValue("rp", rp);
        cmd.Parameters.AddWithValue("origin", origin);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        var result = (reader.GetGuid(0), reader.GetString(1),
            reader.GetFieldValue<DateTimeOffset>(2),
            reader.GetFieldValue<DateTimeOffset>(3));
        Assert.False(await reader.ReadAsync());
        return result;
    }

    [Fact]
    public async Task OwnerCannotPinIpAddressOversizedDnsLabelOrNumericTldAsReviewerRp()
    {
        await using var owner = Owner();
        await owner.OpenAsync();
        foreach (var rp in new[]
        {
            "127.0.0.1",
            new string('a', 64) + ".example.org",
            "review.example.123",
            "review..example.org",
            "review.example.org."
        })
        {
            var issuer = "https://identity.example.org/realms/" + Guid.NewGuid().ToString("N");
            await using var cmd = new NpgsqlCommand("""
                INSERT INTO public.reviewer_registration_rp_policies
                    (identity_issuer,rp_id,trusted_origin,change_reference)
                VALUES (@issuer,@rp,@origin,'CAB-REJECTED-INPUT')
                """, owner);
            cmd.Parameters.AddWithValue("issuer", issuer);
            cmd.Parameters.AddWithValue("rp", rp);
            cmd.Parameters.AddWithValue("origin", "https://" + rp);
            var error = await Assert.ThrowsAsync<PostgresException>(
                async () => await cmd.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
        }
    }

    [Fact]
    public async Task RegistrarIsNoLoginWithNoMembersAndOnlyNarrowExecutePermission()
    {
        await using var db = Owner();
        await db.OpenAsync();
        await using var cmd = new NpgsqlCommand("""
            SELECT (SELECT NOT rolcanlogin FROM pg_catalog.pg_roles
                    WHERE rolname='temporalmark_credential_registrar_group'),
                NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_auth_members
                    WHERE roleid='temporalmark_credential_registrar_group'::regrole),
                has_function_privilege('temporalmark_credential_registrar_group',
                    'public.issue_reviewer_registration_intent(text,text,text,text,text)',
                    'EXECUTE'),
                has_function_privilege('temporalmark_approver_group',
                    'public.issue_reviewer_registration_intent(text,text,text,text,text)',
                    'EXECUTE'),
                has_function_privilege('temporalmark_provisioner_group',
                    'public.issue_reviewer_registration_intent(text,text,text,text,text)',
                    'EXECUTE'),
                has_function_privilege('temporalmark_runtime_group',
                    'public.issue_reviewer_registration_intent(text,text,text,text,text)',
                    'EXECUTE'),
                has_table_privilege('temporalmark_credential_registrar_group',
                    'public.reviewer_registration_intents','SELECT,INSERT,UPDATE,DELETE'),
                has_table_privilege('temporalmark_credential_registrar_group',
                    'public.reviewer_registration_rp_policies','SELECT,INSERT,UPDATE,DELETE'),
                has_table_privilege('temporalmark_approver_group',
                    'public.reviewer_registration_intents','SELECT,INSERT,UPDATE,DELETE'),
                has_table_privilege('temporalmark_provisioner_group',
                    'public.reviewer_registration_intents','SELECT,INSERT,UPDATE,DELETE'),
                has_table_privilege('temporalmark_runtime_group',
                    'public.reviewer_registration_intents','SELECT,INSERT,UPDATE,DELETE')
            """, db);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        for (var i = 0; i < 3; i++) Assert.True(reader.GetBoolean(i));
        for (var i = 3; i < 11; i++) Assert.False(reader.GetBoolean(i));
        Assert.False(await reader.ReadAsync());
    }

    [Fact]
    public async Task OnlyOwnerPinnedHttpsRpAndDistinctRegistrarCanIssueOneUnconsumableIntent()
    {
        var policy = Policy();
        await using var owner = Owner();
        await owner.OpenAsync();

        await Assert.ThrowsAsync<PostgresException>(() => Issue(owner,
            policy.Issuer, policy.Rp, policy.Origin));
        await PinPolicy(owner, policy);

        await Assert.ThrowsAsync<PostgresException>(() => Issue(owner,
            "https://attacker.example.org/realm", policy.Rp, policy.Origin));
        await Assert.ThrowsAsync<PostgresException>(() => Issue(owner,
            policy.Issuer, policy.Rp, "https://attacker.example.org"));
        await Assert.ThrowsAsync<PostgresException>(() => Issue(owner,
            policy.Issuer, policy.Rp, policy.Origin, "same", "same"));
        await Assert.ThrowsAsync<PostgresException>(() => Issue(owner,
            policy.Issuer, policy.Rp, policy.Origin, " reviewer", "registrar"));
        await Assert.ThrowsAsync<PostgresException>(() => Issue(owner,
            policy.Issuer, policy.Rp, policy.Origin, "reviewer", ""));

        var issued = await Issue(owner, policy.Issuer, policy.Rp, policy.Origin);
        Assert.NotEqual(Guid.Empty, issued.Id);
        Assert.Matches("^[0-9A-F]{96}$", issued.Hex);
        Assert.True(issued.Expires > issued.Issued);
        Assert.InRange(issued.Expires - issued.Issued,
            TimeSpan.FromSeconds(1), TimeSpan.FromMinutes(2));
        await Assert.ThrowsAsync<PostgresException>(() =>
            Issue(owner, policy.Issuer, policy.Rp, policy.Origin));
        await Assert.ThrowsAsync<PostgresException>(() =>
            Issue(owner, policy.Issuer, policy.Rp, policy.Origin, registrar:"other-registrar"));

        await using var verify = new NpgsqlCommand("""
            SELECT (SELECT count(*) FROM public.reviewer_registration_intents
                    WHERE identity_issuer=@issuer AND reviewer_subject='reviewer-sub'
                      AND rp_id=@rp),
                   (SELECT count(*) FROM public.organizations WHERE id=@id),
                   (SELECT count(*) FROM public.organization_provisioning_events
                    WHERE organization_id=@id),
                   (SELECT count(*) FROM public.organization_decision_challenges
                    WHERE id=@id)
            """, owner);
        verify.Parameters.AddWithValue("issuer", policy.Issuer);
        verify.Parameters.AddWithValue("rp", policy.Rp);
        verify.Parameters.AddWithValue("id", issued.Id);
        await using var reader = await verify.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());
        Assert.Equal(1L, reader.GetInt64(0));
        for (var i = 1; i < 4; i++) Assert.Equal(0L, reader.GetInt64(i));
    }

    [Fact]
    public async Task OldApproverAndOperatorCannotIssueOrReadPrivateIntents()
    {
        var policy = Policy();
        await using var owner = Owner();
        await owner.OpenAsync();
        await PinPolicy(owner, policy);

        foreach (var conn in new[] { Approver(), Operator() })
        {
            await using (conn)
            {
                await conn.OpenAsync();
                var err = await Assert.ThrowsAsync<PostgresException>(() =>
                    Issue(conn, policy.Issuer, policy.Rp, policy.Origin));
                Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, err.SqlState);
                await using var direct = new NpgsqlCommand("""
                    SELECT count(*) FROM public.reviewer_registration_intents
                    """, conn);
                var denied = await Assert.ThrowsAsync<PostgresException>(
                    async () => await direct.ExecuteScalarAsync());
                Assert.Equal(PostgresErrorCodes.InsufficientPrivilege, denied.SqlState);
            }
        }
    }

    [Fact]
    public async Task OwnerCannotSilentlyEditApprovedRpOrIssuedIntentRows()
    {
        var policy = Policy();
        await using var owner = Owner();
        await owner.OpenAsync();
        await PinPolicy(owner, policy);
        var intent = await Issue(owner, policy.Issuer, policy.Rp, policy.Origin);
        foreach (var sql in new[]
        {
            "UPDATE public.reviewer_registration_rp_policies SET change_reference='changed' WHERE rp_id=@rp",
            "DELETE FROM public.reviewer_registration_rp_policies WHERE rp_id=@rp",
            "UPDATE public.reviewer_registration_intents SET registrar_subject='other' WHERE id=@id",
            "DELETE FROM public.reviewer_registration_intents WHERE id=@id"
        })
        {
            await using var cmd = new NpgsqlCommand(sql, owner);
            cmd.Parameters.AddWithValue("rp", policy.Rp);
            cmd.Parameters.AddWithValue("id", intent.Id);
            var error = await Assert.ThrowsAsync<PostgresException>(
                async () => await cmd.ExecuteNonQueryAsync());
            Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
        }
    }

    [Fact]
    public async Task ConcurrentRegistrarIntentIssuanceCreatesExactlyOneRow()
    {
        var policy = Policy();
        await using (var setup = Owner())
        {
            await setup.OpenAsync();
            await PinPolicy(setup, policy);
        }
        async Task<(bool Created, string? Error)> Race()
        {
            await using var connection = Owner();
            await connection.OpenAsync();
            try
            {
                var issued = await Issue(connection, policy.Issuer, policy.Rp, policy.Origin);
                return (issued.Id != Guid.Empty, null);
            }
            catch (PostgresException error)
            {
                return (false, error.SqlState);
            }
        }
        var results = await Task.WhenAll(Race(), Race());
        Assert.Single(results, result => result.Created);
        Assert.Single(results, result =>
            !result.Created && result.Error == PostgresErrorCodes.UniqueViolation);
        await using var owner = Owner();
        await owner.OpenAsync();
        await using var check = new NpgsqlCommand("""
            SELECT count(*) FROM public.reviewer_registration_intents
            WHERE identity_issuer=@issuer AND rp_id=@rp AND reviewer_subject='reviewer-sub'
            """, owner);
        check.Parameters.AddWithValue("issuer", policy.Issuer);
        check.Parameters.AddWithValue("rp", policy.Rp);
        Assert.Equal(1L, Assert.IsType<long>(await check.ExecuteScalarAsync()));
    }
}
