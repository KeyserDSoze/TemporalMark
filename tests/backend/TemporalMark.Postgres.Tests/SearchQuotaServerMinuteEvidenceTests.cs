using Xunit;

namespace TemporalMark.Postgres.Tests;

/// <summary>
/// #135 / ADR 0101 RED-first contract for test-only evidence acceptance.
/// Do not mistake a request spanning two server epoch-minute buckets for a
/// breach of V019's fixed-window tenant/principal quotas.
/// </summary>
public sealed class SearchQuotaServerMinuteEvidenceTests
{
    [Fact]
    public async Task WindowRolloverDiscardsInconclusiveAttemptAndRunsFreshScenario()
    {
        // The tested decision is deterministic: two separate windows never
        // produce a conclusive 31st-admission assertion. In actual integration
        // tests, these samples come from PostgreSQL clock_timestamp().
        var samples = new Queue<long>([123, 124, 124, 124]);
        var attempts = 0;
        var conclusive = await SearchQuotaServerMinuteEvidence.RunAsync(
            () => Task.FromResult(samples.Dequeue()),
            () => Task.FromResult(++attempts));

        Assert.Equal(2, attempts);
        Assert.Equal(2, conclusive);
        Assert.Empty(samples);
    }

    [Fact]
    public async Task ThreeConsecutiveBoundaryCrossingsFailClosedWithoutInfiniteRetry()
    {
        var samples = new Queue<long>([123, 124, 124, 125, 125, 126]);
        var attempts = 0;
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            SearchQuotaServerMinuteEvidence.RunAsync(
                () => Task.FromResult(samples.Dequeue()),
                () => Task.FromResult(++attempts)));

        Assert.Equal(3, attempts);
        Assert.Empty(samples);
        Assert.DoesNotContain("principal", failure.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SqlScenarioFailureIsNeverTreatedAsClockBoundaryFlakiness()
    {
        var samples = new Queue<long>([123]);
        var attempts = 0;
        var failure = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            SearchQuotaServerMinuteEvidence.RunAsync(
                () => Task.FromResult(samples.Dequeue()),
                () =>
                {
                    attempts++;
                    throw new InvalidOperationException("DENIED-SQL-PRIVILEGE-CANARY");
#pragma warning disable CS0162
                    return Task.FromResult(1);
#pragma warning restore CS0162
                }));

        Assert.Equal(1, attempts);
        Assert.Contains("DENIED-SQL-PRIVILEGE-CANARY", failure.Message);
    }
}
