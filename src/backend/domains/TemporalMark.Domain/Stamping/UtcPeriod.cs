namespace TemporalMark.Domain.Stamping;

/// <summary>UTC half-open interval [FromUtc, ToUtcExclusive).</summary>
public sealed record UtcPeriod
{
    public DateTimeOffset FromUtc { get; }
    public DateTimeOffset ToUtcExclusive { get; }

    public UtcPeriod(DateTimeOffset fromUtc, DateTimeOffset toUtcExclusive)
    {
        if (fromUtc.Offset != TimeSpan.Zero || toUtcExclusive.Offset != TimeSpan.Zero)
            throw new ArgumentException("Time bounds must use UTC (+00:00).");
        if (fromUtc >= toUtcExclusive)
            throw new ArgumentException("The end of the period must be after the start.");
        FromUtc = fromUtc;
        ToUtcExclusive = toUtcExclusive;
    }

    public bool Contains(DateTimeOffset timestamp) =>
        timestamp >= FromUtc && timestamp < ToUtcExclusive;
}
