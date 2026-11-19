using TemporalMark.Business.Registry;
using TemporalMark.Domain.Stamping;
using Xunit;

namespace TemporalMark.Business.Tests;

/// <summary>RED-first: rate decision is only from signed-principal scope, never a queried imprint.</summary>
public sealed class ImprintSearchRateGateServiceTests
{
    private static readonly Guid Tenant = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private static readonly UtcPeriod Period = new(
        new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero),
        new DateTimeOffset(2026, 12, 1, 0, 0, 0, TimeSpan.Zero));

    [Fact]
    public async Task AllowedSearchUsesOnlyTenantAndAuthenticatedSubject()
    {
        var backend = new StubGateRepository
        {
            Decision = new ImprintSearchRateDecision(true, 0)
        };
        var gate = new ImprintSearchRateGateService(backend);
        var decision = await gate.TryAcquireAsync(Tenant, "oidc-admin-A", default);

        Assert.True(decision.Allowed);
        Assert.Equal(0, decision.RetryAfterSeconds);
        Assert.Equal(Tenant, backend.Tenant);
        Assert.Equal("oidc-admin-A", backend.Subject);
        Assert.Equal(1, backend.Calls);
    }

    [Fact]
    public async Task DeniedDecisionCarriesOnlyBoundedRetrySeconds()
    {
        var backend = new StubGateRepository
        {
            Decision = new ImprintSearchRateDecision(false, 37)
        };
        var response = await new ImprintSearchRateGateService(backend).TryAcquireAsync(
            Tenant, "oidc-admin-A", default);
        Assert.False(response.Allowed);
        Assert.Equal(37, response.RetryAfterSeconds);
    }

    [Theory]
    [InlineData(true, 1)]
    [InlineData(false, 0)]
    [InlineData(false, 61)]
    [InlineData(false, -1)]
    [InlineData(true, 60)]
    public async Task MaliciousOrCorruptRepositoryResultFailsClosed(bool allow, int retry)
    {
        var backend = new StubGateRepository
        {
            Decision = new ImprintSearchRateDecision(allow, retry)
        };
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new ImprintSearchRateGateService(backend).TryAcquireAsync(Tenant, "oidc-admin-A", default));
    }

    [Fact]
    public async Task InvalidIdentityIsRejectedWithoutBackendTraffic()
    {
        var backend = new StubGateRepository();
        var gate = new ImprintSearchRateGateService(backend);
        await Assert.ThrowsAsync<ArgumentException>(() =>
            gate.TryAcquireAsync(Guid.Empty, "oidc-admin-A", default));
        foreach (var subject in new[] { "", " ", "with\ncontrol", " padded", new string('x', 256) })
            await Assert.ThrowsAsync<ArgumentException>(() =>
                gate.TryAcquireAsync(Tenant, subject, default));
        Assert.Equal(0, backend.Calls);
    }

    [Fact]
    public async Task UnavailableSharedGateIsNotSilentlyBypassed()
    {
        var backend = new StubGateRepository { Fail = true };
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new ImprintSearchRateGateService(backend).TryAcquireAsync(Tenant, "oidc-admin-A", default));
    }

    [Theory]
    [InlineData("", 0, 50)]
    [InlineData("0x1111", 0, 50)]
    [InlineData("1111111111111111111111111111111111111111111111111111111111111111", -1, 50)]
    [InlineData("1111111111111111111111111111111111111111111111111111111111111111", 0, 51)]
    public void PreflightRejectsBadSearchBeforeQuotaAndRegistry(string digest, int offset, int limit)
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            TimestampRegistryService.ValidateDocumentImprintSearchRequest(Tenant, Period, digest, offset, limit));
    }

    [Fact]
    public void PreflightAcceptsExactHexWithoutCreatingTenantOrDigestRateKey()
    {
        TimestampRegistryService.ValidateDocumentImprintSearchRequest(
            Tenant, Period, new string('A', 64), 0, 50);
    }

    private sealed class StubGateRepository : IImprintSearchRateRepository
    {
        public Guid Tenant { get; private set; }
        public string? Subject { get; private set; }
        public int Calls { get; private set; }
        public bool Fail { get; set; }
        public ImprintSearchRateDecision Decision { get; set; } = new(true, 0);

        public Task<ImprintSearchRateDecision> ConsumeAsync(
            Guid tenant, string actorSubjectId, CancellationToken ct)
        {
            Calls++;
            Tenant = tenant;
            Subject = actorSubjectId;
            if (Fail) throw new InvalidOperationException("PostgreSQL rate gate unavailable");
            return Task.FromResult(Decision);
        }
    }
}
