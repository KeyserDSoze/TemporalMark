using TemporalMark.Domain.Stamping;

namespace TemporalMark.Business.Stamping;

public interface ITimestampWriter
{
    Task AppendAsync(TimestampRecord record, CancellationToken cancellationToken);
}
