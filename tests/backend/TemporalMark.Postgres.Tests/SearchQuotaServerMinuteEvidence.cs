namespace TemporalMark.Postgres.Tests;

/// <summary>
/// #135 / ADR 0101: test-only evidence helper. A fixed 60-second PostgreSQL
/// epoch-minute quota cannot be asserted from a scenario spanning two buckets.
/// Callers MUST query the actual PostgreSQL server clock_timestamp() and create
/// a fresh disposable test tenant for each attempt. This class never changes
/// production SQL, retries a denied SQL operation or skips an assertion.
/// </summary>
internal static class SearchQuotaServerMinuteEvidence
{
    private const int MaximumFreshScenarioAttempts = 3;

    /// <summary>
    /// Returns only a scenario whose real PostgreSQL epoch-minute is identical
    /// immediately before and after every SQL admission and evidence query.
    /// A minute crossing makes that observation INCONCLUSIVE (the SQL may
    /// legitimately reset); no production request is retried by this helper.
    /// SQL errors, invalid replies and authorization failures propagate.
    /// </summary>
    internal static async Task<T> RunAsync<T>(
        Func<Task<long>> readPostgresEpochMinute,
        Func<Task<T>> runFreshDisposableTenantScenario)
    {
        ArgumentNullException.ThrowIfNull(readPostgresEpochMinute);
        ArgumentNullException.ThrowIfNull(runFreshDisposableTenantScenario);

        for (var attempt = 0; attempt < MaximumFreshScenarioAttempts; attempt++)
        {
            var before = await readPostgresEpochMinute();
            var evidence = await runFreshDisposableTenantScenario();
            var after = await readPostgresEpochMinute();

            if (before == after)
                return evidence;
        }

        // Never weaken or silently pass a rate/security assertion if the
        // runner repeatedly crosses server minute boundaries.
        throw new InvalidOperationException(
            "PostgreSQL server epoch-minute changed during each bounded quota test scenario");
    }
}
