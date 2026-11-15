using TemporalMark.Domain.Stamping;
using Xunit;

namespace TemporalMark.Domain.Tests;

public sealed class UtcPeriodTests
{
    [Fact]
    public void IsStartInclusiveAndEndExclusive()
    {
        var from = new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
        var to = from.AddDays(1);
        var period = new UtcPeriod(from, to);
        Assert.True(period.Contains(from));
        Assert.False(period.Contains(to));
    }

    [Fact]
    public void RejectsInvertedOrEmptyRange()
    {
        var from = DateTimeOffset.UtcNow;
        Assert.Throws<ArgumentException>(() => new UtcPeriod(from, from));
        Assert.Throws<ArgumentException>(() => new UtcPeriod(from, from.AddSeconds(-1)));
    }

    [Fact]
    public void RejectsNonUtcInputs()
    {
        Assert.Throws<ArgumentException>(() =>
            new UtcPeriod(new DateTimeOffset(2026, 11, 1, 0, 0, 0, TimeSpan.FromHours(2)), DateTimeOffset.UtcNow.AddDays(1)));
    }
}
