using System.Security.Cryptography;
using Npgsql;
using TemporalMark.Business.Registry;
using TemporalMark.Domain.Stamping;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// #181 / ADR 0139. Owner-inserted V001 historical evidence on disposable
/// PG17 (NOT via the now-strict application writer or production SQL grants).
/// Tests insist that the pilot read and v1 ZIP policies agree on PolicyOid.
/// </summary>
public sealed class PostgresLegacyPolicyReadTests
{
    private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";
    private static readonly byte[] Der = [0x30, 0x02, 0x01, 0x00];
    private static readonly string Imprint = Convert.ToBase64String(new byte[32]);
    private static readonly string DerSha = Convert.ToHexString(SHA256.HashData(Der));
    private static readonly UtcPeriod Period = new(
        new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));

    private static NpgsqlDataSource Database() =>
        NpgsqlDataSource.Create(
            Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("Disposable PostgreSQL test DB required."));

    private static async Task<Guid> NewTenantAsync(NpgsqlDataSource database)
    {
        var tenant = Guid.NewGuid();
        await using var connection = await database.OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-pg-legacy-policy')",
            connection);
        command.Parameters.AddWithValue("id", tenant);
        command.Parameters.AddWithValue("name", "CI legacy policy " + tenant.ToString("N"));
        Assert.Equal(tenant, Assert.IsType<Guid>(await command.ExecuteScalarAsync()));
        return tenant;
    }

    private static async Task<Guid> InsertHistoricalAsync(
        NpgsqlDataSource database, Guid tenant, string policy)
    {
        await using var connection = await database.OpenConnectionAsync();
        await using var command = new NpgsqlCommand("""
            INSERT INTO public.timestamp_registry
                (id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
                 policy_oid, provider_id, token_sha256_hex, validation_state,
                 response_der, evidence_reference)
            VALUES (@id, @org, @issued, @algorithm, @digest,
                    @policy, 'CI_ORIGINAL_LEGACY_POLICY', @sha, 0, @der, NULL::text)
            """, connection);
        var id = Guid.NewGuid();
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("org", tenant);
        command.Parameters.AddWithValue("issued",
            new DateTime(2026, 11, 15, 9, 0, 0, DateTimeKind.Utc));
        command.Parameters.AddWithValue("algorithm", Sha256Oid);
        command.Parameters.AddWithValue("digest", Imprint);
        command.Parameters.AddWithValue("policy", policy);
        command.Parameters.AddWithValue("sha", DerSha);
        command.Parameters.AddWithValue("der", Der);
        Assert.Equal(1, await command.ExecuteNonQueryAsync());
        return id;
    }

    private static string BadPolicy(string caseName) => caseName switch
    {
        "empty" => "",
        "spaces" => "   ",
        "tab" => "\t",
        "unicode-nbsp" => "\u00A0",
        _ => throw new InvalidOperationException("Invalid fixed fixture.")
    };

    [Theory]
    [InlineData("empty", "page")]
    [InlineData("empty", "receipt")]
    [InlineData("empty", "search")]
    [InlineData("empty", "export")]
    [InlineData("spaces", "page")]
    [InlineData("spaces", "receipt")]
    [InlineData("spaces", "search")]
    [InlineData("spaces", "export")]
    [InlineData("tab", "page")]
    [InlineData("tab", "receipt")]
    [InlineData("tab", "search")]
    [InlineData("tab", "export")]
    [InlineData("unicode-nbsp", "page")]
    [InlineData("unicode-nbsp", "receipt")]
    [InlineData("unicode-nbsp", "search")]
    [InlineData("unicode-nbsp", "export")]
    public async Task OriginalLegacyBlankPolicyRefusesAuthorizedEvidenceRead(
        string badCase, string route)
    {
        await using var database = Database();
        var tenant = await NewTenantAsync(database);
        var foreign = await NewTenantAsync(database);
        var sourcePolicy = BadPolicy(badCase);
        var id = await InsertHistoricalAsync(database, tenant, sourcePolicy);

        var repository = new PostgresTimestampRegistry(database);
        var original = await repository.FindByIdAsync(tenant, id, default);
        Assert.NotNull(original);
        original.Validate(); // Existing Domain DER hash/IDs/UTC/signer are valid.
        Assert.Equal(sourcePolicy, original.PolicyOid);
        Assert.Equal(Sha256Oid, original.HashAlgorithmOid);
        Assert.Equal(Imprint, original.DigestBase64);
        Assert.Equal(Der, original.ResponseDer);
        Assert.Equal(DerSha, original.TokenSha256Hex);
        Assert.Equal(TimestampValidationState.Unverified, original.ValidationState);
        Assert.Null(await repository.FindByIdAsync(foreign, id, default));

        var service = new TimestampRegistryService(repository);
        Func<Task> read = route switch
        {
            "page" => async () =>
            {
                _ = await service.PageAsync(tenant, Period, 0, 10, default);
            },
            "receipt" => async () =>
            {
                _ = await service.DownloadReceiptAsync(tenant, id, default);
            },
            "search" => async () =>
            {
                _ = await service.SearchByDocumentSha256Async(
                    tenant, Period, new string('0', 64), 0, 1, default);
            },
            "export" => async () =>
            {
                _ = await service.ExportZipAsync(tenant, Period, default);
            },
            _ => throw new InvalidOperationException("Invalid fixed route.")
        };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(read);
        Assert.Equal("Repository returned an unsupported pilot policy identifier.", error.Message);
        Assert.DoesNotContain(tenant.ToString(), error.Message);
        Assert.DoesNotContain(id.ToString(), error.Message);
        Assert.DoesNotContain(Sha256Oid, error.Message);
        Assert.DoesNotContain(Imprint, error.Message);
        Assert.DoesNotContain(DerSha, error.Message);

        // Denying delivery never normalizes, deletes or rewrites source rows.
        var preserved = await repository.FindByIdAsync(tenant, id, default);
        Assert.NotNull(preserved);
        Assert.Equal(sourcePolicy, preserved.PolicyOid);
        Assert.Equal(Der, preserved.ResponseDer);
        Assert.Null(await service.DownloadReceiptAsync(foreign, id, default));
        Assert.Empty(await service.PageAsync(foreign, Period, 0, 10, default));
        Assert.Empty((await service.SearchByDocumentSha256Async(
            foreign, Period, new string('0', 64), 0, 1, default)).Items);
    }

    [Fact]
    public async Task HistoricalNonblankPolicyAtExactSixteenKiBRemainsOwnerReadable()
    {
        await using var database = Database();
        var own = await NewTenantAsync(database);
        var other = await NewTenantAsync(database);
        var policy = new string('P', 16 * 1024);
        var id = await InsertHistoricalAsync(database, own, policy);
        var service = new TimestampRegistryService(new PostgresTimestampRegistry(database));

        Assert.Equal(policy, Assert.Single(await service.PageAsync(
            own, Period, 0, 10, default)).PolicyOid);
        Assert.Equal(policy, Assert.Single((await service.SearchByDocumentSha256Async(
            own, Period, new string('0', 64), 0, 1, default)).Items).PolicyOid);
        Assert.Equal(Der, await service.DownloadReceiptAsync(own, id, default));
        Assert.NotEmpty(await service.ExportZipAsync(own, Period, default));
        Assert.Null(await service.DownloadReceiptAsync(other, id, default));
    }
}
