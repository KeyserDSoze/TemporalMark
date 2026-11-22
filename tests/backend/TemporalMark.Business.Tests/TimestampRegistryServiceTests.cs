using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using TemporalMark.Business.Registry;
using TemporalMark.Domain;
using TemporalMark.Domain.Stamping;
using Xunit;

namespace TemporalMark.Business.Tests;

public sealed class TimestampRegistryServiceTests
{
    private static readonly Guid TenantA = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly Guid TenantB = Guid.Parse("22222222-2222-2222-2222-222222222222");
    private static readonly UtcPeriod Period = new(
        new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));

    // #156 / ADR 0121: only Unverified is supported by actual issuance.
    // An otherwise valid, tenant-owned record must not declare a future
    // qualification or incident status on any registry read boundary.
    [Theory]
    [InlineData(TimestampValidationState.VerifiedNonQualified, "page")]
    [InlineData(TimestampValidationState.VerifiedNonQualified, "search")]
    [InlineData(TimestampValidationState.VerifiedNonQualified, "receipt")]
    [InlineData(TimestampValidationState.VerifiedNonQualified, "export")]
    [InlineData(TimestampValidationState.VerifiedQualifiedExternal, "page")]
    [InlineData(TimestampValidationState.VerifiedQualifiedExternal, "search")]
    [InlineData(TimestampValidationState.VerifiedQualifiedExternal, "receipt")]
    [InlineData(TimestampValidationState.VerifiedQualifiedExternal, "export")]
    [InlineData(TimestampValidationState.VerifiedQualifiedOwn, "page")]
    [InlineData(TimestampValidationState.VerifiedQualifiedOwn, "search")]
    [InlineData(TimestampValidationState.VerifiedQualifiedOwn, "receipt")]
    [InlineData(TimestampValidationState.VerifiedQualifiedOwn, "export")]
    [InlineData(TimestampValidationState.AffectedByIncident, "page")]
    [InlineData(TimestampValidationState.AffectedByIncident, "search")]
    [InlineData(TimestampValidationState.AffectedByIncident, "receipt")]
    [InlineData(TimestampValidationState.AffectedByIncident, "export")]
    public async Task PilotRegistryReadRejectsUnsupportedVerificationStatus(
        TimestampValidationState unsupportedState, string readBoundary)
    {
        var record = MakeRecord(TenantA) with { ValidationState = unsupportedState };
        // The existing domain validator deliberately permits future states:
        // prove every failing test is about the missing pilot read gate,
        // not corrupt bytes, checksum, tenant or issuance timestamp.
        record.Validate();
        Assert.Equal(
            Convert.ToHexString(SHA256.HashData(record.ResponseDer)),
            record.TokenSha256Hex);

        var registry = new FakeRegistry([record]);
        var service = new TimestampRegistryService(registry);
        Func<Task> read = readBoundary switch
        {
            "page" => async () =>
            {
                _ = await service.PageAsync(TenantA, Period, 0, 25, default);
            },
            "search" => async () =>
            {
                _ = await service.SearchByDocumentSha256Async(
                    TenantA, Period, new string('0', 64), 0, 25, default);
            },
            "receipt" => async () =>
            {
                _ = await service.DownloadReceiptAsync(TenantA, record.Id, default);
            },
            "export" => async () =>
            {
                _ = await service.ExportZipAsync(TenantA, Period, default);
            },
            _ => throw new InvalidOperationException("Unexpected fixed test route")
        };

        var error = await Assert.ThrowsAsync<InvalidOperationException>(read);
        // The caller must not learn an unsupported qualified-state label,
        // token digest, tenant ID or issuer name via exception details.
        Assert.DoesNotContain(unsupportedState.ToString(), error.ToString());
        Assert.DoesNotContain(TenantA.ToString(), error.ToString());
        Assert.DoesNotContain(record.ProviderId, error.ToString());
        Assert.DoesNotContain(record.TokenSha256Hex, error.ToString());
    }

    // #169 / ADR 0127 — the ZIP and offline v1 verifier reject
    // individual DER >1 MiB, but GET /receipt also needs that pilot guard.
    [Fact]
    public async Task DownloadReceiptRejectsOversizedShaConsistentPilotDer()
    {
        var der = new byte[1024 * 1024 + 1];
        var oversized = MakeRecord(TenantA) with
        {
            ResponseDer = der,
            TokenSha256Hex = Convert.ToHexString(SHA256.HashData(der))
        };
        // Prove this is NOT a corrupted hash/record fixture: only the
        // missing single-receipt resource budget can cause the denial.
        oversized.Validate();
        var exception = await Assert.ThrowsAnyAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new FakeRegistry([oversized]))
                .DownloadReceiptAsync(TenantA, oversized.Id, default));
        Assert.DoesNotContain(TenantA.ToString(), exception.Message);
        Assert.DoesNotContain(oversized.TokenSha256Hex, exception.Message);
        Assert.DoesNotContain(oversized.ProviderId, exception.Message);
    }

    [Fact]
    public async Task DownloadReceiptAcceptsExactOneMiBPilotBoundaryUnmodified()
    {
        var der = new byte[1024 * 1024];
        var receipt = MakeRecord(TenantA) with
        {
            ResponseDer = der,
            TokenSha256Hex = Convert.ToHexString(SHA256.HashData(der))
        };
        var downloaded = await new TimestampRegistryService(new FakeRegistry([receipt]))
            .DownloadReceiptAsync(TenantA, receipt.Id, default);
        Assert.Equal(der, downloaded);
    }

    [Fact]
    public async Task DownloadReceiptCrossTenantAndUnknownRemainDeniedEvenIfDerIsOversized()
    {
        var der = new byte[1024 * 1024 + 1];
        var foreign = MakeRecord(TenantB) with
        {
            ResponseDer = der,
            TokenSha256Hex = Convert.ToHexString(SHA256.HashData(der))
        };
        foreign.Validate();
        var denied = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new MaliciousRegistry(foreign))
                .DownloadReceiptAsync(TenantA, foreign.Id, default));
        Assert.Equal("Repository returned a record outside authorized tenant.", denied.Message);

        var missing = await new TimestampRegistryService(new FakeRegistry([]))
            .DownloadReceiptAsync(TenantA, foreign.Id, default);
        Assert.Null(missing);
    }

    [Fact]
    public async Task DownloadReceiptRejectsCrossTenantLeak()
    {
        var other = MakeRecord(TenantB);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new MaliciousRegistry(other)).DownloadReceiptAsync(
                TenantA, other.Id, default));
    }

    [Fact]
    public async Task DownloadReceiptForOwnerReturnsExactDer()
    {
        var own = MakeRecord(TenantA);
        var result = await new TimestampRegistryService(new FakeRegistry([own])).DownloadReceiptAsync(
            TenantA, own.Id, default);
        Assert.Equal(own.ResponseDer, result);
    }

    [Fact]
    public async Task SearchByDocumentSha256IsTenantBoundPagedAndCanonicalizesHex()
    {
        // The document imprint is distinct from SHA256(ResponseDer).
        var documentDigest = Enumerable.Range(0, 32).Select(i => (byte)(i * 7)).ToArray();
        var canonicalHex = Convert.ToHexString(documentDigest);
        var canonicalBase64 = Convert.ToBase64String(documentDigest);
        var own = MakeRecord(TenantA) with { DigestBase64 = canonicalBase64 };
        var data = new[]
        {
            own,
            own with { Id = Guid.NewGuid(), IssuedUtc = own.IssuedUtc.AddMinutes(1) },
            own with { Id = Guid.NewGuid(), IssuedUtc = own.IssuedUtc.AddMinutes(2) },
            MakeRecord(TenantB) with { DigestBase64 = canonicalBase64 },
            MakeRecord(TenantA) with { DigestBase64 = Convert.ToBase64String(new byte[32]) },
            own with { Id = Guid.NewGuid(), IssuedUtc = Period.ToUtcExclusive }
        };
        var repo = new FakeRegistry(data);
        var service = new TimestampRegistryService(repo);
        var page0 = await service.SearchByDocumentSha256Async(
            TenantA, Period, canonicalHex.ToLowerInvariant(), 0, 2, default);
        Assert.Equal(2, page0.Items.Count);
        Assert.True(page0.HasMore);
        Assert.All(page0.Items, item => Assert.Equal(TenantA, item.OrganizationId));
        Assert.All(page0.Items, item => Assert.Equal(canonicalBase64, item.DigestBase64));
        Assert.Equal(canonicalBase64, repo.LastSearchDigestBase64);
        var page2 = await service.SearchByDocumentSha256Async(
            TenantA, Period, canonicalHex, 2, 2, default);
        Assert.Single(page2.Items);
        Assert.False(page2.HasMore);
        Assert.Equal(2, repo.SearchQueries);
    }

    [Fact]
    public async Task SearchByDocumentSha256ReturnsEmptyWhenNoMatch()
    {
        var repo = new FakeRegistry([MakeRecord(TenantA)]);
        var missing = Convert.ToHexString(Enumerable.Repeat((byte)0xF1, 32).ToArray());
        var result = await new TimestampRegistryService(repo)
            .SearchByDocumentSha256Async(TenantA, Period, missing, 0, 50, default);
        Assert.Empty(result.Items);
        Assert.False(result.HasMore);
        Assert.Equal(1, repo.SearchQueries);
    }

    [Fact]
    public async Task SearchByDocumentSha256RejectsBadImprintsAndPagingBeforeRepository()
    {
        const string good = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
        var bad = new[]
        {
            "", " ", "0x" + good, good + "0", good[..63],
            " " + good[1..], good[..20] + "!" + good[21..],
            good[..32] + "\n" + good[33..], new string('A', 100000)
        };
        foreach (var value in bad)
        {
            var repo = new FakeRegistry([]);
            await Assert.ThrowsAsync<ArgumentException>(() =>
                new TimestampRegistryService(repo).SearchByDocumentSha256Async(
                    TenantA, Period, value, 0, 50, default));
            Assert.Equal(0, repo.SearchQueries);
        }
        foreach (var (org, offset, limit) in new[]
        {
            (Guid.Empty, 0, 50), (TenantA, -1, 50),
            (TenantA, 0, 0), (TenantA, 0, 51)
        })
        {
            var repo = new FakeRegistry([]);
            await Assert.ThrowsAnyAsync<ArgumentException>(() =>
                new TimestampRegistryService(repo).SearchByDocumentSha256Async(
                    org, Period, good, offset, limit, default));
            Assert.Equal(0, repo.SearchQueries);
        }
    }

    [Fact]
    public async Task SearchByDocumentSha256RejectsUntrustedRepositoryRowsBeforeReply()
    {
        var owned = MakeRecord(TenantA);
        var hex = new string('0', 64);
        var rows = new IReadOnlyList<TimestampRecord>[]
        {
            [MakeRecord(TenantB)],
            [owned with { DigestBase64 = Convert.ToBase64String(Enumerable.Repeat((byte)0xFF, 32).ToArray()) }],
            [owned with { HashAlgorithmOid = "1.3.14.3.2.26" }],
            [owned with { IssuedUtc = Period.ToUtcExclusive }],
            [owned, owned]
        };
        foreach (var data in rows)
        {
            var repo = new FakeRegistry([], overrideSearch: data);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                new TimestampRegistryService(repo).SearchByDocumentSha256Async(
                    TenantA, Period, hex, 0, 50, default));
            Assert.Equal(1, repo.SearchQueries);
        }
        var corrupt = owned with { TokenSha256Hex = "DEADBEEF" };
        await Assert.ThrowsAsync<DomainRuleException>(() =>
            new TimestampRegistryService(new FakeRegistry([], overrideSearch: [corrupt]))
                .SearchByDocumentSha256Async(TenantA, Period, hex, 0, 50, default));
    }

    // #168 / ADR 0126: the real PG repository returns ordered, bounded
    // batches; the Business read boundary must not trust a buggy adapter.
    [Fact]
    public async Task PageRejectsValidButOverLimitRepositoryBatch()
    {
        var first = MakeRecord(TenantA);
        var second = first with { Id = Guid.NewGuid(), IssuedUtc = first.IssuedUtc.AddMinutes(1) };
        first.Validate();
        second.Validate();
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new FakeRegistry([], overridePage: [first, second]))
                .PageAsync(TenantA, Period, 0, 1, default));
        Assert.DoesNotContain(TenantA.ToString(), error.Message);
        Assert.DoesNotContain(first.ProviderId, error.Message);
    }

    [Fact]
    public async Task PageRejectsDescendingIssuedUtcDespiteValidTenantAndDer()
    {
        var earlier = MakeRecord(TenantA);
        var later = earlier with { Id = Guid.NewGuid(), IssuedUtc = earlier.IssuedUtc.AddMinutes(1) };
        earlier.Validate();
        later.Validate();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new FakeRegistry([], overridePage: [later, earlier]))
                .PageAsync(TenantA, Period, 0, 2, default));
    }

    [Fact]
    public async Task PageRejectsDescendingCanonicalUuidWhenIssuedUtcTies()
    {
        var smaller = MakeRecord(TenantA) with
        {
            Id = Guid.Parse("10000000-0000-0000-0000-000000000001")
        };
        var larger = smaller with
        {
            Id = Guid.Parse("20000000-0000-0000-0000-000000000002")
        };
        smaller.Validate();
        larger.Validate();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new FakeRegistry([], overridePage: [larger, smaller]))
                .PageAsync(TenantA, Period, 0, 2, default));
    }

    [Fact]
    public async Task SearchRejectsDescendingIssuedUtcInLookaheadBeforeHasMore()
    {
        var earlier = MakeRecord(TenantA);
        var later = earlier with { Id = Guid.NewGuid(), IssuedUtc = earlier.IssuedUtc.AddMinutes(1) };
        earlier.Validate();
        later.Validate();
        // Two otherwise-valid matches for limit=1: the second *lookahead*
        // record may not be skipped by the ordering check.
        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new FakeRegistry([], overrideSearch: [later, earlier]))
                .SearchByDocumentSha256Async(TenantA, Period, new string('0', 64), 0, 1, default));
        Assert.DoesNotContain(TenantA.ToString(), error.Message);
        Assert.DoesNotContain(new string('0', 64), error.Message);
    }

    [Fact]
    public async Task SearchRejectsDescendingCanonicalUuidInLookaheadTie()
    {
        var smaller = MakeRecord(TenantA) with
        {
            Id = Guid.Parse("10000000-0000-0000-0000-000000000001")
        };
        var larger = smaller with
        {
            Id = Guid.Parse("20000000-0000-0000-0000-000000000002")
        };
        smaller.Validate();
        larger.Validate();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new FakeRegistry([], overrideSearch: [larger, smaller]))
                .SearchByDocumentSha256Async(TenantA, Period, new string('0', 64), 0, 1, default));
    }

    [Fact]
    public async Task PageAndSearchAcceptStrictlySortedSameUtcIdTie()
    {
        var smaller = MakeRecord(TenantA) with
        {
            Id = Guid.Parse("10000000-0000-0000-0000-000000000001")
        };
        var larger = smaller with
        {
            Id = Guid.Parse("20000000-0000-0000-0000-000000000002")
        };
        var rows = new[] { smaller, larger };
        var repository = new FakeRegistry([], overridePage: rows, overrideSearch: rows);
        var registry = new TimestampRegistryService(repository);

        var page = await registry.PageAsync(TenantA, Period, 0, 2, default);
        Assert.Equal(new[] { smaller.Id, larger.Id }, page.Select(x => x.Id).ToArray());

        var search = await registry.SearchByDocumentSha256Async(
            TenantA, Period, new string('0', 64), 0, 1, default);
        Assert.Equal(smaller.Id, Assert.Single(search.Items).Id);
        Assert.True(search.HasMore);
    }

    [Fact]
    public async Task PageRejectsRepositoryCrossTenantLeak()
    {
        var repository = new MaliciousRegistry(MakeRecord(TenantB));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(repository).PageAsync(TenantA, Period, 0, 50, default));
    }

    [Fact]
    public async Task PageForOwnerStillReturnsOneIntegrityCheckedRecord()
    {
        var record = MakeRecord(TenantA);
        var page = await new TimestampRegistryService(new FakeRegistry([record])).PageAsync(
            TenantA, Period, 0, 25, CancellationToken.None);
        Assert.Single(page);
        Assert.Equal(record, page[0]);
    }

    [Fact]
    public async Task PageRejectsCorruptedStoredReceiptDigest()
    {
        var record = MakeRecord(TenantA) with { TokenSha256Hex = "DEADBEEF" };
        await Assert.ThrowsAsync<DomainRuleException>(() =>
            new TimestampRegistryService(new FakeRegistry([record])).PageAsync(
                TenantA, Period, 0, 25, CancellationToken.None));
    }

    [Fact]
    public async Task PageRejectsTamperedDerEvenIfStoredDigestIsUnchanged()
    {
        var intact = MakeRecord(TenantA);
        var corrupt = intact with { ResponseDer = [0x30, 0x02, 0x01, 0x01] };
        await Assert.ThrowsAsync<DomainRuleException>(() =>
            new TimestampRegistryService(new FakeRegistry([corrupt])).PageAsync(
                TenantA, Period, 0, 25, CancellationToken.None));
    }

    [Fact]
    public async Task PageRejectsDuplicateIdsBeforeReturningAnyMetadata()
    {
        var sameId = MakeRecord(TenantA);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new FakeRegistry([sameId, sameId])).PageAsync(
                TenantA, Period, 0, 25, CancellationToken.None));
    }

    [Fact]
    public async Task ExportRejectsDuplicateReceiptIdsRatherThanProducingAmbiguousZipPaths()
    {
        var sameId = MakeRecord(TenantA);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(new FakeRegistry([sameId, sameId]))
                .ExportZipAsync(TenantA, Period, CancellationToken.None));
    }

    [Fact]
    public async Task DailyCountIsTenantBoundAndIncludesEmptyUtcDays()
    {
        var start = new DateTimeOffset(2026, 11, 15, 0, 0, 0, TimeSpan.Zero);
        var period = new UtcPeriod(start, start.AddDays(3));
        var a = MakeRecord(TenantA);
        var values = new[]
        {
            a,
            a with { Id = Guid.NewGuid(), IssuedUtc = start.AddHours(23) },
            a with { Id = Guid.NewGuid(), IssuedUtc = start.AddDays(2).AddHours(1) },
            MakeRecord(TenantB) with { IssuedUtc = start.AddHours(1) },
            a with { Id = Guid.NewGuid(), IssuedUtc = start.AddDays(3) } // exclusive end
        };
        var repo = new FakeRegistry(values);

        var result = await new TimestampRegistryService(repo).DailyAsync(
            TenantA, period, CancellationToken.None);

        Assert.Equal(TenantA, result.OrganizationId);
        Assert.Equal(start, result.FromUtc);
        Assert.Equal(start.AddDays(3), result.ToUtcExclusive);
        Assert.Equal(new long[] { 2, 0, 1 }, result.Days.Select(x => x.Count).ToArray());
        Assert.Equal(new[]
        {
            new DateOnly(2026, 11, 15), new DateOnly(2026, 11, 16), new DateOnly(2026, 11, 17)
        }, result.Days.Select(x => x.DateUtc).ToArray());
        Assert.Equal(1, repo.DailyQueries);
    }

    [Fact]
    public async Task DailyAllowsInclusive31DayRangeButNoMore()
    {
        var repo = new FakeRegistry([]);
        var start = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
        var result = await new TimestampRegistryService(repo).DailyAsync(
            TenantA, new UtcPeriod(start, start.AddDays(31)), default);
        Assert.Equal(31, result.Days.Count);
        Assert.All(result.Days, x => Assert.Equal(0, x.Count));
        Assert.Equal(new DateOnly(2026, 12, 1), result.Days[^1].DateUtc);
    }

    [Fact]
    public async Task DailyRejectsUnalignedOrOverlongPeriodsBeforeQuery()
    {
        var start = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
        foreach (var period in new[]
        {
            new UtcPeriod(start.AddMinutes(1), start.AddDays(1)),
            new UtcPeriod(start, start.AddDays(1).AddMinutes(1)),
            new UtcPeriod(start, start.AddDays(32))
        })
        {
            var repo = new FakeRegistry([]);
            await Assert.ThrowsAsync<ArgumentException>(() =>
                new TimestampRegistryService(repo).DailyAsync(TenantA, period, default));
            Assert.Equal(0, repo.DailyQueries);
        }
    }

    [Fact]
    public async Task DailyRejectsEmptyTenantBeforeQuery()
    {
        var repo = new FakeRegistry([]);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new TimestampRegistryService(repo).DailyAsync(
                Guid.Empty, new UtcPeriod(
                    new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
                    new DateTimeOffset(2026, 11, 2, 0, 0, 0, TimeSpan.Zero)), default));
        Assert.Equal(0, repo.DailyQueries);
    }

    [Fact]
    public async Task DailyRejectsMalformedRepositorySeriesWithoutReturningPartialStats()
    {
        var one = new DateOnly(2026, 11, 15);
        var period = new UtcPeriod(
            new DateTimeOffset(2026, 11, 15, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 11, 17, 0, 0, 0, TimeSpan.Zero));
        var malformed = new IReadOnlyList<RegistryDayCount>[]
        {
            [new RegistryDayCount(one, 1), new RegistryDayCount(one, 1)],
            [new RegistryDayCount(one.AddDays(-1), 1)],
            [new RegistryDayCount(one.AddDays(2), 1)],
            [new RegistryDayCount(one, 0)],
            [new RegistryDayCount(one, -1)]
        };
        foreach (var series in malformed)
        {
            var repo = new FakeRegistry([], series);
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                new TimestampRegistryService(repo).DailyAsync(TenantA, period, default));
            Assert.Equal(1, repo.DailyQueries);
        }
    }

    [Fact]
    public async Task ExportContainsDerAndManifestForAuthorizedTenant()
    {
        var fake = new FakeRegistry(new[] { MakeRecord(TenantA), MakeRecord(TenantB) });
        var zipBytes = await new TimestampRegistryService(fake).ExportZipAsync(TenantA, Period, default);
        using var archive = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read);
        Assert.Equal(2, archive.Entries.Count);
        using var manifest = JsonDocument.Parse(archive.GetEntry("manifest.json")!.Open());
        Assert.Equal(1, manifest.RootElement.GetProperty("count").GetInt32());
        Assert.Equal(TenantA.ToString(), manifest.RootElement.GetProperty("organizationId").GetString());
    }

    [Fact]
    public async Task ExportRejectsCrossTenantRepositoryBug()
    {
        var malicious = new MaliciousRegistry(MakeRecord(TenantB));
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new TimestampRegistryService(malicious).ExportZipAsync(TenantA, Period, default));
    }

    [Fact]
    public async Task ExportRejectsCorruptStoredToken()
    {
        var valid = MakeRecord(TenantA);
        var damaged = valid with { TokenSha256Hex = "ABCD" };
        await Assert.ThrowsAsync<DomainRuleException>(() =>
            new TimestampRegistryService(new MaliciousRegistry(damaged)).ExportZipAsync(TenantA, Period, default));
    }

    [Fact]
    public async Task ExportRejectsSingleOverOneMiBReceiptBeforeCreatingZip()
    {
        // RED-first #106. Even a self-consistent legacy stored receipt
        // cannot bypass the synchronous API's per-receipt byte budget.
        var oversizedDer = new byte[1024 * 1024 + 1];
        var receipt = MakeRecord(TenantA) with
        {
            ResponseDer = oversizedDer,
            TokenSha256Hex = Convert.ToHexString(SHA256.HashData(oversizedDer))
        };

        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            new TimestampRegistryService(new FakeRegistry([receipt]))
                .ExportZipAsync(TenantA, Period, CancellationToken.None));
    }

    [Fact]
    public async Task ExportRejectsCumulativeOver64MiBDerForDistinctValidReceipts()
    {
        // Reuse a single 1 MiB buffer across 65 independently identified
        // self-consistent receipts; avoids 65 MiB of fixture allocations.
        var der = new byte[1024 * 1024];
        var seed = MakeRecord(TenantA) with
        {
            ResponseDer = der,
            TokenSha256Hex = Convert.ToHexString(SHA256.HashData(der))
        };
        var distinct = Enumerable.Range(0, 65)
            .Select(_ => seed with { Id = Guid.NewGuid() }).ToArray();

        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            new TimestampRegistryService(new FakeRegistry(distinct))
                .ExportZipAsync(TenantA, Period, CancellationToken.None));
    }

    // #166 / ADR 0124: an ordinary compressed ZIP can hide an oversized
    // *uncompressed* manifest that our own strict v1 offline verifier denies.
    // Stored DER and SHA, tenant, UTC and Unverified state are all valid.
    [Fact]
    public async Task ExportRejectsSingleOversizedJsonManifestBeforeReturningZip()
    {
        var receipt = MakeRecord(TenantA) with
        {
            EvidenceReference = new string('X', 8 * 1024 * 1024)
        };

        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            new TimestampRegistryService(new FakeRegistry([receipt]))
                .ExportZipAsync(TenantA, Period, CancellationToken.None));
    }

    [Fact]
    public async Task ExportRejectsAggregateMetadataOverEightMiBDespiteSmallReceipts()
    {
        // Each record is well below 8 MiB and all rows share the same
        // allocation; only their combined serialized manifest is too large.
        var sharedReference = new string('Q', 1024 * 1024);
        var rows = Enumerable.Range(0, 9)
            .Select(_ => MakeRecord(TenantA) with
            {
                EvidenceReference = sharedReference
            }).ToArray();

        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            new TimestampRegistryService(new FakeRegistry(rows))
                .ExportZipAsync(TenantA, Period, CancellationToken.None));
    }

    [Fact]
    public async Task ExportRejectsEscapedUnicodeJsonBytesRatherThanCountingCSharpChars()
    {
        // System.Text.Json escapes non-ASCII chars by default. This short
        // 1.5M-char string expands past 8 MiB in serialized JSON UTF-8.
        var receipt = MakeRecord(TenantA) with
        {
            EvidenceReference = new string('\u00e9', 1_500_000)
        };

        await Assert.ThrowsAsync<ExportTooLargeException>(() =>
            new TimestampRegistryService(new FakeRegistry([receipt]))
                .ExportZipAsync(TenantA, Period, CancellationToken.None));
    }

    [Fact]
    public async Task ExportAcceptsLargeButInBudgetJsonManifestAndPreservesMetadata()
    {
        var reference = new string('R', 7 * 1024 * 1024);
        var receipt = MakeRecord(TenantA) with { EvidenceReference = reference };
        var zipBytes = await new TimestampRegistryService(new FakeRegistry([receipt]))
            .ExportZipAsync(TenantA, Period, CancellationToken.None);

        Assert.True(zipBytes.LongLength <= 80L * 1024 * 1024);
        using var zip = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read);
        var manifest = zip.GetEntry("manifest.json");
        Assert.NotNull(manifest);
        Assert.InRange(manifest!.Length, 1, 8L * 1024 * 1024);
        using var json = JsonDocument.Parse(manifest.Open());
        Assert.Equal(reference, json.RootElement.GetProperty("entries")[0]
            .GetProperty("EvidenceReference").GetString());
        Assert.NotNull(zip.GetEntry($"tokens/{receipt.Id:N}.tsr"));
    }

    [Fact]
    public async Task ExportAcceptsOneMiBReceiptAtInclusivePerReceiptBoundary()
    {
        var der = new byte[1024 * 1024];
        var valid = MakeRecord(TenantA) with
        {
            ResponseDer = der,
            TokenSha256Hex = Convert.ToHexString(SHA256.HashData(der))
        };

        var bytes = await new TimestampRegistryService(new FakeRegistry([valid]))
            .ExportZipAsync(TenantA, Period, CancellationToken.None);
        using var archive = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
        using var content = new MemoryStream();
        await using (var entryStream = archive.GetEntry($"tokens/{valid.Id:N}.tsr")!.Open())
            await entryStream.CopyToAsync(content);
        Assert.Equal(der, content.ToArray());
        using var manifest = JsonDocument.Parse(archive.GetEntry("manifest.json")!.Open());
        Assert.Equal(1, manifest.RootElement.GetProperty("count").GetInt32());
    }

    private static TimestampRecord MakeRecord(Guid tenant)
    {
        var der = new byte[] { 0x30, 0x02, 0x01, 0x00 };
        return new TimestampRecord(Guid.NewGuid(), tenant,
            new DateTimeOffset(2026, 11, 15, 9, 0, 0, TimeSpan.Zero),
            "2.16.840.1.101.3.4.2.1", Convert.ToBase64String(new byte[32]),
            "1.2.3", "test-provider", Convert.ToHexString(SHA256.HashData(der)),
            TimestampValidationState.Unverified, der, null);
    }

    private sealed class FakeRegistry(
        IReadOnlyList<TimestampRecord> data,
        IReadOnlyList<RegistryDayCount>? overrideDays = null,
        IReadOnlyList<TimestampRecord>? overrideSearch = null,
        IReadOnlyList<TimestampRecord>? overridePage = null) : ITimestampRegistry
    {
        public int DailyQueries { get; private set; }
        public int SearchQueries { get; private set; }
        public string? LastSearchDigestBase64 { get; private set; }
        public Task<IReadOnlyList<TimestampRecord>> SearchByDigestAsync(
            Guid org, UtcPeriod period, string digestBase64, int offset, int maxResults,
            CancellationToken ct)
        {
            SearchQueries++;
            LastSearchDigestBase64 = digestBase64;
            return Task.FromResult(overrideSearch ?? (IReadOnlyList<TimestampRecord>)
                Filter(org, period)
                    .Where(x => x.HashAlgorithmOid == "2.16.840.1.101.3.4.2.1" &&
                                x.DigestBase64 == digestBase64)
                    .OrderBy(x => x.IssuedUtc).ThenBy(x => x.Id)
                    .Skip(offset).Take(maxResults).ToArray());
        }
        public Task<IReadOnlyList<RegistryDayCount>> CountByUtcDayAsync(
            Guid org, UtcPeriod period, CancellationToken ct)
        {
            DailyQueries++;
            return Task.FromResult(overrideDays ?? (IReadOnlyList<RegistryDayCount>)
                Filter(org, period)
                    .GroupBy(x => DateOnly.FromDateTime(x.IssuedUtc.UtcDateTime))
                    .OrderBy(x => x.Key)
                    .Select(x => new RegistryDayCount(x.Key, x.LongCount()))
                    .ToArray());
        }

        private IEnumerable<TimestampRecord> Filter(Guid org, UtcPeriod period) =>
            data.Where(x => x.OrganizationId == org && period.Contains(x.IssuedUtc));
        public Task<TimestampRecord?> FindByIdAsync(Guid org, Guid id, CancellationToken ct) =>
            Task.FromResult(data.FirstOrDefault(x => x.OrganizationId == org && x.Id == id));
        public Task<long> CountAsync(Guid org, UtcPeriod period, CancellationToken ct) =>
            Task.FromResult((long)Filter(org, period).Count());
        public Task<IReadOnlyList<TimestampRecord>> PageAsync(Guid org, UtcPeriod period, int offset, int limit, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<TimestampRecord>>(overridePage ?? Filter(org, period).Skip(offset).Take(limit).ToArray());
        public Task<IReadOnlyList<TimestampRecord>> ForExportAsync(Guid org, UtcPeriod period, int max, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<TimestampRecord>>(Filter(org, period).Take(max).ToArray());
    }

    private sealed class MaliciousRegistry(TimestampRecord record) : ITimestampRegistry
    {
        public Task<IReadOnlyList<TimestampRecord>> SearchByDigestAsync(
            Guid org, UtcPeriod period, string digestBase64, int offset, int maxResults,
            CancellationToken ct) => Task.FromResult<IReadOnlyList<TimestampRecord>>([record]);
        public Task<TimestampRecord?> FindByIdAsync(Guid org, Guid id, CancellationToken ct) => Task.FromResult<TimestampRecord?>(record);
        public Task<long> CountAsync(Guid org, UtcPeriod period, CancellationToken ct) => Task.FromResult(1L);
        public Task<IReadOnlyList<RegistryDayCount>> CountByUtcDayAsync(Guid org, UtcPeriod period, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<RegistryDayCount>>([new RegistryDayCount(new DateOnly(2026, 11, 15), 1)]);
        public Task<IReadOnlyList<TimestampRecord>> PageAsync(Guid org, UtcPeriod period, int off, int lim, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<TimestampRecord>>(new[] { record });
        public Task<IReadOnlyList<TimestampRecord>> ForExportAsync(Guid org, UtcPeriod period, int max, CancellationToken ct) =>
            Task.FromResult<IReadOnlyList<TimestampRecord>>(new[] { record });
    }
}
