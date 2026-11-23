using System.Security.Cryptography;
using Npgsql;
using TemporalMark.Domain.Stamping;
using TemporalMark.Infrastructure.Postgres;
using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// #177 / ADR 0135: direct PostgreSQL writer must not create newly-issued
/// pilot receipts that the existing registry reader will refuse.
/// Uses disposable real PG17 and original SHA-consistent (not qualified) DER.
/// </summary>
public sealed class PostgresTimestampWriterAdmissibilityTests
{
    private const int TextLimit = 16 * 1024;
    private const int DerLimit = 1024 * 1024;
    private const int ReferenceLimit = 8 * 1024 * 1024;

    private static NpgsqlDataSource Database() =>
        NpgsqlDataSource.Create(
            Environment.GetEnvironmentVariable("TEMPORALMARK_TEST_DB")
            ?? throw new InvalidOperationException("Disposable PostgreSQL test DB required."));

    private static async Task<Guid> NewTenantAsync(NpgsqlDataSource db)
    {
        var tenant = Guid.NewGuid();
        await using var connection = await db.OpenConnectionAsync();
        await using var command = new NpgsqlCommand(
            "SELECT public.bootstrap_organization(@id, @name, 'ci-pg-writer-admission')",
            connection);
        command.Parameters.AddWithValue("id", tenant);
        command.Parameters.AddWithValue("name", "CI writer admission " + tenant.ToString("N"));
        Assert.Equal(tenant, Assert.IsType<Guid>(await command.ExecuteScalarAsync()));
        return tenant;
    }

    private static TimestampRecord Record(
        Guid tenant, string policy = "1.2.3", string provider = "CI_WRITER_ADMISSION",
        byte[]? der = null, string? evidenceReference = null)
    {
        var original = der ?? new byte[] { 0x30, 0x02, 0x01, 0x00 };
        return new TimestampRecord(
            Guid.NewGuid(), tenant,
            new DateTimeOffset(2026, 11, 15, 9, 0, 0, TimeSpan.Zero),
            "2.16.840.1.101.3.4.2.1",
            Convert.ToBase64String(new byte[32]), policy, provider,
            Convert.ToHexString(SHA256.HashData(original)),
            TimestampValidationState.Unverified, original, evidenceReference);
    }

    [Theory]
    [InlineData("oversized-algorithm")]
    [InlineData("oversized-imprint-text")]
    [InlineData("oversized-provider")]
    [InlineData("oversized-policy")]
    [InlineData("multibyte-provider")]
    [InlineData("oversized-der")]
    [InlineData("oversized-reference")]
    [InlineData("empty-policy")]
    public async Task DirectWriterRefusesNewUnretrievableReceiptBeforeInsert(
        string variant)
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        var receipt = variant switch
        {
            "oversized-algorithm" => Record(tenant) with
            {
                HashAlgorithmOid = new string('H', TextLimit + 1)
            },
            "oversized-imprint-text" => Record(tenant) with
            {
                DigestBase64 = new string('D', TextLimit + 1)
            },
            "oversized-provider" => Record(tenant,
                provider: new string('P', TextLimit + 1)),
            "oversized-policy" => Record(tenant,
                policy: new string('1', TextLimit + 1)),
            "multibyte-provider" => Record(tenant,
                provider: new string('é', TextLimit / 2 + 1)),
            "oversized-der" => Record(tenant,
                der: new byte[DerLimit + 1]),
            "oversized-reference" => Record(tenant,
                evidenceReference: new string('R', ReferenceLimit + 1)),
            "empty-policy" => Record(tenant, policy: ""),
            _ => throw new InvalidOperationException()
        };
        // Deliberately original/own-tenant, SHA-consistent, pilot Unverified.
        // Bad metadata isn't a pre-existing cryptographic hash failure.
        receipt.Validate();
        Assert.Equal(tenant, receipt.OrganizationId);

        var denied = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new PostgresTimestampWriter(db).AppendAsync(receipt, default));
        Assert.Equal("Stored receipt exceeds pilot registry write limits.", denied.Message);
        Assert.DoesNotContain(tenant.ToString(), denied.Message);
        Assert.DoesNotContain(receipt.Id.ToString(), denied.Message);

        // A database constraint-only refusal would be too late and could
        // leak original metadata; test that NO row was saved.
        await using var connection = await db.OpenConnectionAsync();
        await using var check = new NpgsqlCommand(
            "SELECT count(*) FROM public.timestamp_registry WHERE organization_id=@org AND id=@id",
            connection);
        check.Parameters.AddWithValue("org", tenant);
        check.Parameters.AddWithValue("id", receipt.Id);
        Assert.Equal(0L, Assert.IsType<long>(await check.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task BoundaryAcceptedReceiptRemainsOriginalReadableAndTenantScoped()
    {
        await using var db = Database();
        var a = await NewTenantAsync(db);
        var b = await NewTenantAsync(db);
        var originalDer = new byte[DerLimit];
        originalDer[0] = 0x30;
        originalDer[^1] = 0x11;
        var originalProvider = new string('I', TextLimit);
        var originalPolicy = new string('2', TextLimit);
        var receipt = Record(a, policy: originalPolicy,
            provider: originalProvider, der: originalDer);

        await new PostgresTimestampWriter(db).AppendAsync(receipt, default);

        var repo = new PostgresTimestampRegistry(db);
        var actual = await repo.FindByIdAsync(a, receipt.Id, default);
        Assert.NotNull(actual);
        Assert.Equal(receipt.Id, actual.Id);
        Assert.Equal(originalDer, actual.ResponseDer);
        Assert.Equal(originalProvider, actual.ProviderId);
        Assert.Equal(originalPolicy, actual.PolicyOid);
        Assert.Null(actual.EvidenceReference);
        Assert.Equal(TimestampValidationState.Unverified, actual.ValidationState);
        actual.Validate();

        Assert.Null(await repo.FindByIdAsync(b, receipt.Id, default));
        Assert.Null(await repo.FindByIdAsync(a, Guid.NewGuid(), default));
    }

    [Fact]
    public async Task NormalSmallReceiptRemainsAppendableAndQueryable()
    {
        await using var db = Database();
        var a = await NewTenantAsync(db);
        var receipt = Record(a);
        await new PostgresTimestampWriter(db).AppendAsync(receipt, default);
        var actual = await new PostgresTimestampRegistry(db)
            .FindByIdAsync(a, receipt.Id, default);
        Assert.NotNull(actual);
        Assert.Equal(receipt.ResponseDer, actual.ResponseDer);
        Assert.Equal(receipt.TokenSha256Hex, actual.TokenSha256Hex);
    }

    // #178 / ADR 0136: V001 and Domain permit future status values, but a
    // direct NEW pilot append must never persist a status that existing
    // Page/Search/Receipt/ZIP read gates refuse. Real PG17, not a mock.
    [Theory]
    [InlineData(TimestampValidationState.VerifiedNonQualified)]
    [InlineData(TimestampValidationState.VerifiedQualifiedExternal)]
    [InlineData(TimestampValidationState.VerifiedQualifiedOwn)]
    [InlineData(TimestampValidationState.AffectedByIncident)]
    public async Task DirectWriterRefusesUnsupportedNewPilotStateBeforeInsert(
        TimestampValidationState unsupportedState)
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        var receipt = Record(tenant) with { ValidationState = unsupportedState };

        // Distinguish a missing NEW-append admission gate from a preexisting
        // Domain rejection, malformed DER, bad SHA or unauthorized tenant.
        receipt.Validate();
        Assert.Equal(tenant, receipt.OrganizationId);
        Assert.Equal(unsupportedState, receipt.ValidationState);

        var denied = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new PostgresTimestampWriter(db).AppendAsync(receipt, default));
        Assert.Equal("Stored receipt exceeds pilot registry write limits.", denied.Message);
        Assert.DoesNotContain(unsupportedState.ToString(), denied.Message);
        Assert.DoesNotContain(tenant.ToString(), denied.Message);
        Assert.DoesNotContain(receipt.Id.ToString(), denied.Message);

        await using var connection = await db.OpenConnectionAsync();
        await using var check = new NpgsqlCommand(
            "SELECT count(*) FROM public.timestamp_registry WHERE organization_id=@org AND id=@id",
            connection);
        check.Parameters.AddWithValue("org", tenant);
        check.Parameters.AddWithValue("id", receipt.Id);
        Assert.Equal(0L, Assert.IsType<long>(await check.ExecuteScalarAsync()));
    }

    // #179 / ADR 0137: the SHA-256 pilot's NEW direct-writer admission
    // must preserve the same canonical document imprint contract as issuer
    // ingress and exact-imprint Search, not merely bound metadata bytes.
    // These run against real disposable PG17; original DER and its stored
    // SHA256 stay consistent to isolate the missing imprint policy gate.
    [Theory]
    [InlineData("wrong-algorithm")]
    [InlineData("oid-alias")]
    [InlineData("leading-whitespace")]
    [InlineData("embedded-whitespace")]
    [InlineData("invalid-alphabet")]
    [InlineData("nonzero-unused-pad-bits")]
    [InlineData("decoded-31-bytes")]
    [InlineData("decoded-33-bytes")]
    [InlineData("missing-padding")]
    [InlineData("urlsafe-alphabet")]
    public async Task DirectWriterRejectsNoncanonicalSha256DocumentImprintBeforeInsert(
        string variant)
    {
        await using var db = Database();
        var tenant = await NewTenantAsync(db);
        var canonical = Convert.ToBase64String(new byte[32]);
        var receipt = Record(tenant);
        receipt = variant switch
        {
            "wrong-algorithm" => receipt with
            {
                HashAlgorithmOid = "1.3.14.3.2.26"
            },
            "oid-alias" => receipt with
            {
                HashAlgorithmOid = "2.16.840.1.101.3.4.2.01"
            },
            "leading-whitespace" => receipt with
            {
                DigestBase64 = " " + canonical
            },
            "embedded-whitespace" => receipt with
            {
                DigestBase64 = canonical.Insert(12, "\t")
            },
            "invalid-alphabet" => receipt with
            {
                DigestBase64 = canonical[..7] + "!" + canonical[8..]
            },
            // Alias decodes to the *same* 32 bytes as all-zero canonical.
            // Only exact ordinal round-trip checks catch unused pad bits.
            "nonzero-unused-pad-bits" => receipt with
            {
                DigestBase64 = canonical[..42] + "B="
            },
            // Both serialize to 44 characters, so length-only admission
            // is insufficient. The decoded length must be precisely 32.
            "decoded-31-bytes" => receipt with
            {
                DigestBase64 = Convert.ToBase64String(new byte[31])
            },
            "decoded-33-bytes" => receipt with
            {
                DigestBase64 = Convert.ToBase64String(new byte[33])
            },
            "missing-padding" => receipt with
            {
                DigestBase64 = canonical.TrimEnd('=')
            },
            "urlsafe-alphabet" => receipt with
            {
                DigestBase64 = Convert.ToBase64String(
                    Enumerable.Repeat((byte)0xff, 32).ToArray()).Replace('/', '_')
            },
            _ => throw new InvalidOperationException("Unknown regression case.")
        };

        receipt.Validate(); // Demonstrates no preexisting Domain rejection.
        Assert.Equal(TimestampValidationState.Unverified, receipt.ValidationState);
        Assert.Equal(tenant, receipt.OrganizationId);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(receipt.ResponseDer)),
            receipt.TokenSha256Hex);
        if (variant == "nonzero-unused-pad-bits")
        {
            Assert.Equal(32, Convert.FromBase64String(receipt.DigestBase64).Length);
            Assert.Equal(new byte[32], Convert.FromBase64String(receipt.DigestBase64));
        }

        var denied = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new PostgresTimestampWriter(db).AppendAsync(receipt, default));
        Assert.Equal("Stored receipt exceeds pilot registry write limits.", denied.Message);
        Assert.DoesNotContain(tenant.ToString(), denied.Message);
        Assert.DoesNotContain(receipt.Id.ToString(), denied.Message);
        Assert.DoesNotContain(receipt.DigestBase64, denied.Message);
        Assert.DoesNotContain(receipt.HashAlgorithmOid, denied.Message);

        await using var connection = await db.OpenConnectionAsync();
        await using var check = new NpgsqlCommand(
            "SELECT count(*) FROM public.timestamp_registry WHERE organization_id=@org AND id=@id",
            connection);
        check.Parameters.AddWithValue("org", tenant);
        check.Parameters.AddWithValue("id", receipt.Id);
        Assert.Equal(0L, Assert.IsType<long>(await check.ExecuteScalarAsync()));
    }

    [Fact]
    public async Task NonzeroCanonicalSha256NewImprintPersistsOriginalAndRemainsTenantScoped()
    {
        await using var db = Database();
        var a = await NewTenantAsync(db);
        var b = await NewTenantAsync(db);
        var originalDigest = Enumerable.Range(0, 32)
            .Select(i => (byte)i).ToArray();
        var canonical = Convert.ToBase64String(originalDigest);
        Assert.Equal(44, canonical.Length);
        var receipt = Record(a) with { DigestBase64 = canonical };
        receipt.Validate();

        await new PostgresTimestampWriter(db).AppendAsync(receipt, default);

        var repository = new PostgresTimestampRegistry(db);
        var persisted = await repository.FindByIdAsync(a, receipt.Id, default);
        Assert.NotNull(persisted);
        Assert.Equal(canonical, persisted.DigestBase64);
        Assert.Equal(receipt.HashAlgorithmOid, persisted.HashAlgorithmOid);
        Assert.Equal(receipt.ResponseDer, persisted.ResponseDer);
        Assert.Equal(receipt.TokenSha256Hex, persisted.TokenSha256Hex);
        Assert.Equal(TimestampValidationState.Unverified, persisted.ValidationState);
        persisted.Validate();
        Assert.Null(await repository.FindByIdAsync(b, receipt.Id, default));
    }
}
