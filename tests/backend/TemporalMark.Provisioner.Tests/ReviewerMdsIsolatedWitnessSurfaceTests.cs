using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first: a separate PostgreSQL witness reader type MUST exist before
/// the integration fixture may reconcile a restored main database. Merely
/// having this shape never approves any signed FIDO root or credential.
/// </summary>
public sealed class ReviewerMdsIsolatedWitnessSurfaceTests
{
    [Fact]
    public void StandaloneWitnessResultCannotExposeTrustedOrActiveAuthorization()
    {
        Assert.Equal("ReviewerMdsIsolatedPostgresWitnessReader",
            typeof(ReviewerMdsIsolatedPostgresWitnessReader).Name);
        Assert.Equal("ReviewerMdsIsolatedPostgresWitnessCandidate",
            typeof(ReviewerMdsIsolatedPostgresWitnessCandidate).Name);
        Assert.DoesNotContain(
            typeof(ReviewerMdsIsolatedPostgresWitnessCandidate).GetProperties(),
            property => property.Name.Contains("Trusted", StringComparison.OrdinalIgnoreCase) ||
                        property.Name.Contains("Approved", StringComparison.OrdinalIgnoreCase) ||
                        property.Name.Contains("Active", StringComparison.OrdinalIgnoreCase) ||
                        property.Name.Contains("PublicKey", StringComparison.OrdinalIgnoreCase));
    }
}
