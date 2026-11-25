namespace TemporalMark.Domain.Documents;

/// <summary>
/// A declared source category, not a legally reviewed classification.
/// Unknown is the safe default; no category confers fiscal eligibility.
/// </summary>
public enum DocumentSourceClass
{
    Unknown = 0,
    NativeDigital = 1,
    AnalogNonUnique = 2,
    AnalogUnique = 3,
    Excluded = 4
}
