namespace TemporalMark.Business.Registry;

/// <summary>Admission only; this is NOT a search-result or qualified-evidence decision.</summary>
public sealed record ImprintSearchRateDecision(bool Allowed, int RetryAfterSeconds);

/// <summary>
/// Consumes one tenant and principal budget in the same shared PostgreSQL transaction.
/// Does not accept document imprints or a caller-selected tenant selector.
/// </summary>
public interface IImprintSearchRateRepository
{
    Task<ImprintSearchRateDecision> ConsumeAsync(
        Guid organizationId, string actorSubjectId, CancellationToken cancellationToken);
}

/// <summary>Fail closed if admission is unavailable or corrupt.</summary>
public sealed class ImprintSearchRateGateService(IImprintSearchRateRepository repository)
{
    public async Task<ImprintSearchRateDecision> TryAcquireAsync(
        Guid organizationId, string actorSubjectId, CancellationToken cancellationToken)
    {
        if (organizationId == Guid.Empty)
            throw new ArgumentException("Organization must come from validated identity.", nameof(organizationId));
        if (string.IsNullOrWhiteSpace(actorSubjectId) || actorSubjectId.Length > 255 ||
            actorSubjectId != actorSubjectId.Trim() || actorSubjectId.Any(char.IsControl))
            throw new ArgumentException("A bounded verified OIDC subject is required.", nameof(actorSubjectId));

        var decision = await repository.ConsumeAsync(organizationId, actorSubjectId, cancellationToken);
        if ((decision.Allowed && decision.RetryAfterSeconds != 0) ||
            (!decision.Allowed && decision.RetryAfterSeconds is < 1 or > 60))
            throw new InvalidOperationException("Rate gate returned an invalid admission decision.");
        return decision;
    }
}
