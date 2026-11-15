using System.Security.Cryptography;
using TemporalMark.Business.Tenancy;
using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// Real Fido2 4.3.3 packed certificate-key signature tests. These deliberately
/// do not use a fake IFido2 and never trust the ephemeral test-only attestor.
/// </summary>
public sealed class ReviewerPackedAttestationCryptographyTests
{
    private static readonly ReviewerWebAuthnRelyingPartyPolicy Rp =
        new("review.example.org", "https://review.example.org");

    [Fact]
    public async Task RealSignedPackedRegistrationReturnsOnlyUnapprovedHashes()
    {
        using var fixture = PackedAttestationTestFixture.Create();
        var result = await ReviewerRegistrationAttestationCandidateVerifier.Create(Rp)
            .VerifyCandidateAsync(fixture.Ceremony, fixture.Options, fixture.Response,
                fixture.TestOnlyUniqueCredentialId);
        Assert.Equal("UNAPPROVED", result.ReviewStatus);
        Assert.Equal("packed", result.AttestationFormat);
        Assert.Equal("basic", result.AttestationType);
        Assert.Equal("review.example.org", result.RelyingPartyId);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(fixture.CredentialId)),
            result.CredentialIdSha256);
        Assert.Equal(64, result.PublicKeySha256.Length);
        Assert.DoesNotContain("PublicKey", typeof(ReviewerAttestationReviewCandidate)
            .GetProperties().Select(p => p.Name).Where(p => p != "PublicKeySha256"));
    }

    [Theory]
    [InlineData("wrong-origin")]
    [InlineData("wrong-challenge")]
    [InlineData("wrong-rp-hash")]
    [InlineData("no-user-presence")]
    [InlineData("no-user-verification")]
    [InlineData("tampered-authenticator-data")]
    [InlineData("tampered-credential-public-key")]
    [InlineData("tampered-attestation-signature")]
    [InlineData("malformed-attestation-certificate")]
    public async Task MutatedPackedAttestationIsDeniedByRealLibrary(string mutation)
    {
        using var fixture = PackedAttestationTestFixture.Create(mutation);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            ReviewerRegistrationAttestationCandidateVerifier.Create(Rp)
                .VerifyCandidateAsync(fixture.Ceremony, fixture.Options, fixture.Response,
                    fixture.TestOnlyUniqueCredentialId));
    }

    [Fact]
    public async Task RealSignedAttestationWithDuplicateCredentialIdMustBeDenied()
    {
        using var fixture = PackedAttestationTestFixture.Create();
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            ReviewerRegistrationAttestationCandidateVerifier.Create(Rp)
                .VerifyCandidateAsync(fixture.Ceremony, fixture.Options, fixture.Response,
                    (_, _) => Task.FromResult(false)));
    }
}
