using System.Security.Cryptography;
using Npgsql;
using TemporalMark.Business.Registry;
using TemporalMark.Domain.Stamping;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// ADR 0140 / #182. Test-only real PG17 owner-inserted historical rows
/// plus direct new writer admission (not broadening production SQL rights).
/// C0 U+001C–U+001F is whitespace under Python .strip(), NOT under
/// .NET string.IsNullOrWhiteSpace, causing the strict offline ZIP mismatch.
/// </summary>
public sealed class PostgresPythonBlankMetadataParityTests
{
    private static readonly UtcPeriod Period = new(
        new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));
    private static readonly byte[] RawDer = [0x30, 0x02, 0x01, 0x00];
    private static readonly string RawDerSha = Convert.ToHexString(SHA256.HashData(RawDer));
    private static readonly string Imprint = Convert.ToBase64String(new byte[32]);
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

    private static NpgsqlDataSource Database() =>
        NpgsqlDataSource.Create(
            Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("Disposable PostgreSQL17 test DB required."));

    private static async Task<Guid> NewTenantAsync(NpgsqlDataSource db)
    {
        var tenant = Guid.NewGuid();
        await using var connection = await db.OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-pg-c0-metadata')",
            connection);
        command.Parameters.AddWithValue("id", tenant);
        command.Parameters.AddWithValue("name", "CI C0 metadata " + tenant.ToString("N"));
        Assert.Equal(tenant, Assert.IsType<Guid>(await command.ExecuteScalarAsync()));
        return tenant;
    }

    private static TimestampRecord Original(
        Guid tenant, string field, string source) =>
        new(
            Guid.NewGuid(), tenant,
            new DateTimeOffset(2026, 11, 15, 9, 0, 0, TimeSpan.Zero),
            Sha256Oid, Imprint,
            field == "policy" ? source : "1.2.3",
            field == "provider" ? source : "CI_ISSUER_PILOT",
            RawDerSha, TimestampValidationState.Unverified, RawDer, null);

    private static string Source(TimestampRecord original, string field) =>
        field == "policy" ? original.PolicyOid : original.ProviderId;

    private static async Task InsertHistoricalAsOwnerAsync(
        NpgsqlDataSource db, TimestampRecord original)
    {
        // Deliberately test-owner SQL bypass: the app NEW writer is
        // separately required to deny these exact source values.
        await using var connection = await db.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO public.timestamp_registry
                (id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
                 policy_oid, provider_id, token_sha256_hex, validation_state,
                 response_der, evidence_reference)
            VALUES (@id, @org, @issued, @algorithm, @digest,
                    @policy, @provider, @sha, @state, @der, NULL::text)
            """, connection);
        cmd.Parameters.AddWithValue("id", original.Id);
        cmd.Parameters.AddWithValue("org", original.OrganizationId);
        cmd.Parameters.AddWithValue("issued", original.IssuedUtc.UtcDateTime);
        cmd.Parameters.AddWithValue("algorithm", original.HashAlgorithmOid);
        cmd.Parameters.AddWithValue("digest", original.DigestBase64);
        cmd.Parameters.AddWithValue("policy", original.PolicyOid);
        cmd.Parameters.AddWithValue("provider", original.ProviderId);
        cmd.Parameters.AddWithValue("sha", original.TokenSha256Hex);
        cmd.Parameters.AddWithValue("state", (short)original.ValidationState);
        cmd.Parameters.AddWithValue("der", original.ResponseDer);
        Assert.Equal(1, await cmd.ExecuteNonQueryAsync());
    }

    private static IEnumerable<string> PythonOnlyBlankValues() =>
        ["\u001c", "\u001d", "\u001e", "\u001f", " \u001c\u00a0\u001f"];

    [Theory]
    [InlineData("policy", "page")]
    [InlineData("policy", "receipt")]
    [InlineData("policy", "search")]
    [InlineData("policy", "export")]
    [InlineData("provider", "page")]
    [InlineData("provider", "receipt")]
    [InlineData("provider", "search")]
    [InlineData("provider", "export")]
    public async Task OwnedRestoredPythonBlankSourceIsNeverDelivered(
        string field, string route)
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        var foreign = await NewTenantAsync(db);
        var repo = new PostgresTimestampRegistry(db);
        var service = new TimestampRegistryService(repo);

        foreach (var source in PythonOnlyBlankValues())
        {
            // This test must isolate the source/read omission from any
            // Domain SHA/UTC/state/other required field failure.
            Assert.False(string.IsNullOrWhiteSpace(source));
            var original = Original(tenant, field, source);
            original.Validate();
            await InsertHistoricalAsOwnerAsync(db, original);
            var raw = await repo.FindByIdAsync(tenant, original.Id, default);
            Assert.NotNull(raw);
            raw.Validate();
            Assert.Equal(source, Source(raw, field));
            Assert.Equal(RawDer, raw.ResponseDer);
            Assert.Equal(RawDerSha, raw.TokenSha256Hex);
            Assert.Null(await repo.FindByIdAsync(foreign, original.Id, default));

            Func<Task> read = route switch
            {
                "page" => async () =>
                {
                    // An earlier valid row with a later bad row also fails
                    // closed; no partial metadata may be returned.
                    _ = await service.PageAsync(tenant, Period, 0, 100, default);
                },
                "receipt" => async () =>
                {
                    _ = await service.DownloadReceiptAsync(
                        tenant, original.Id, default);
                },
                "search" => async () =>
                {
                    _ = await service.SearchByDocumentSha256Async(
                        tenant, Period, new string('0', 64), 0, 50, default);
                },
                "export" => async () =>
                {
                    _ = await service.ExportZipAsync(tenant, Period, default);
                },
                _ => throw new InvalidOperationException("Unknown fixed test route.")
            };

            var denied = await Assert.ThrowsAsync<InvalidOperationException>(read);
            Assert.Equal(
                field == "policy"
                    ? "Repository returned an unsupported pilot policy identifier."
                    : "Repository returned an unsupported pilot provider identifier.",
                denied.Message);
            Assert.DoesNotContain(tenant.ToString(), denied.Message);
            Assert.DoesNotContain(original.Id.ToString(), denied.Message);
            Assert.DoesNotContain(RawDerSha, denied.Message);
            Assert.DoesNotContain(Imprint, denied.Message);

            // No normalization, cleanup, truncation or mutation on refusal.
            var unchanged = await repo.FindByIdAsync(tenant, original.Id, default);
            Assert.NotNull(unchanged);
            Assert.Equal(source, Source(unchanged, field));
            Assert.Equal(RawDer, unchanged.ResponseDer);
            Assert.Null(await service.DownloadReceiptAsync(foreign, original.Id, default));
            Assert.Empty(await service.PageAsync(foreign, Period, 0, 100, default));
        }
    }

    [Theory]
    [InlineData("policy")]
    [InlineData("provider")]
    public async Task DirectNewWriterDeniesPythonBlankSourceBeforeAnySqlInsert(
        string field)
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);

        foreach (var source in PythonOnlyBlankValues())
        {
            var original = Original(tenant, field, source);
            original.Validate();
            Assert.False(string.IsNullOrWhiteSpace(source));

            var error = await Assert.ThrowsAsync<InvalidOperationException>(
                () => new PostgresTimestampWriter(db).AppendAsync(original, default));
            Assert.Equal("Stored receipt exceeds pilot registry write limits.",
                error.Message);
            Assert.DoesNotContain(tenant.ToString(), error.Message);
            Assert.DoesNotContain(original.Id.ToString(), error.Message);

            await using var connection = await db.OpenConnectionAsync();
            await using var cmd = new NpgsqlCommand(
                "SELECT count(*) FROM public.timestamp_registry WHERE organization_id=@org AND id=@id",
                connection);
            cmd.Parameters.AddWithValue("org", tenant);
            cmd.Parameters.AddWithValue("id", original.Id);
            Assert.Equal(0L, Assert.IsType<long>(await cmd.ExecuteScalarAsync()));
        }
    }

    [Fact]
    public async Task PrintableSourceWithEmbeddedSeparatorStaysExactAndTenantIsolated()
    {
        await using var db = Database();
        var a = await NewTenantAsync(db);
        var b = await NewTenantAsync(db);
        var raw = Original(a, "policy", "1.2\u001c.3") with
        {
            ProviderId = "SOURCE\u001fAPP"
        };
        await new PostgresTimestampWriter(db).AppendAsync(raw, default);
        var repo = new PostgresTimestampRegistry(db);
        var svc = new TimestampRegistryService(repo);

        var actual = await repo.FindByIdAsync(a, raw.Id, default);
        Assert.NotNull(actual);
        Assert.Equal(raw.PolicyOid, actual.PolicyOid);
        Assert.Equal(raw.ProviderId, actual.ProviderId);
        Assert.Equal(RawDer, actual.ResponseDer);
        Assert.Equal(raw.Id, Assert.Single(await svc.PageAsync(
            a, Period, 0, 10, default)).Id);
        Assert.Equal(raw.Id, Assert.Single((await svc.SearchByDocumentSha256Async(
            a, Period, new string('0', 64), 0, 1, default)).Items).Id);
        Assert.Equal(RawDer, await svc.DownloadReceiptAsync(a, raw.Id, default));
        Assert.NotEmpty(await svc.ExportZipAsync(a, Period, default));
        Assert.Null(await svc.DownloadReceiptAsync(b, raw.Id, default));
    }
}
