using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Fido2NetLib;
using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// Test FIRST: untrusted MDS model objects test policy only. These are NOT
/// signed MDS BLOB fixtures; no assertion of a trusted manufacturer is made.
/// </summary>
public sealed class ReviewerMdsMetadataPolicyPreflightTests
{
    private static readonly DateTimeOffset Now =
        new(2026, 11, 15, 22, 0, 0, TimeSpan.Zero);
    private static readonly Guid Aaguid = Guid.Parse("60000000-0000-4000-8000-000000000123");

    private static ReviewerAttestationReviewCandidate Candidate(
        string status = "UNAPPROVED", string type = "attca",
        string format = "packed", Guid? aaguid = null,
        bool backedUp = false, bool backupEligible = false) =>
        new(status, "https://identity.example.org", "reviewer", "independent-registrar",
            "review.example.org", new string('A', 64), new string('B', 64),
            type, format, aaguid ?? Aaguid, 0, backupEligible, backedUp);

    private static string TestAnchor()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            "CN=Fake MDS Test Anchor, O=TemporalMark Fixture, C=IT",
            key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        using var cert = request.CreateSelfSigned(Now.AddDays(-1), Now.AddDays(30));
        return Convert.ToBase64String(cert.RawData);
    }

    private static MetadataBLOBPayload Blob() => new()
    {
        Number = 42,
        NextUpdate = "2026-11-17",
        JwtAlg = "RS256", // Untrusted value; does NOT verify a signature.
        Entries =
        [
            new MetadataBLOBPayloadEntry
            {
                AaGuid = Aaguid,
                MetadataStatement = new MetadataStatement
                {
                    AaGuid = Aaguid,
                    ProtocolFamily = "fido2",
                    Schema = 3,
                    AttestationTypes = ["basic_full"],
                    AttestationRootCertificates = [TestAnchor()]
                },
                StatusReports =
                [
                    new StatusReport
                    {
                        Status = AuthenticatorStatus.FIDO_CERTIFIED_L2,
                        EffectiveDate = "2026-11-10"
                    }
                ]
            }
        ]
    };

    private static ReviewerMdsMetadataPolicyObservation Inspect(
        MetadataBLOBPayload? blob = null,
        ReviewerAttestationReviewCandidate? candidate = null,
        int minimumSerial = 40, DateTimeOffset? observed = null) =>
        ReviewerMdsMetadataPolicyPreflight.Inspect(
            candidate ?? Candidate(), blob ?? Blob(), minimumSerial,
            observed ?? Now.AddHours(-1), Now);

    [Fact]
    public void WellFormedSyntheticMetadataIsOnlyUnapprovedPolicyObservation()
    {
        var result = Inspect();
        Assert.Equal("UNAPPROVED", result.ReviewStatus);
        Assert.Equal(Aaguid, result.AuthenticatorAaguid);
        Assert.Equal(42, result.MetadataSerial);
        Assert.Equal("MDS_METADATA_INSPECTION_ONLY", result.PolicyStage);
        Assert.DoesNotContain(typeof(ReviewerMdsMetadataPolicyObservation).GetProperties(),
            p => p.Name is "PublicKey" or "SigningKey" or "Trusted" or "ActiveCredential");
    }

    [Theory]
    [InlineData("REVOKED")]
    [InlineData("USER_VERIFICATION_BYPASS")]
    [InlineData("ATTESTATION_KEY_COMPROMISE")]
    [InlineData("USER_KEY_REMOTE_COMPROMISE")]
    [InlineData("USER_KEY_PHYSICAL_COMPROMISE")]
    [InlineData("RETIRED")]
    [InlineData("UPDATE_AVAILABLE")]
    [InlineData("NOT_FIDO_CERTIFIED")]
    [InlineData("SELF_ASSERTION_SUBMITTED")]
    public void AnyUnsafeReportDeniesEvenIfEarlierCertified(string status)
    {
        var blob = Blob();
        blob.Entries[0].StatusReports =
        [
            new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED_L2 },
            new StatusReport { Status = Enum.Parse<AuthenticatorStatus>(status) }
        ];
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
    }

    [Fact]
    public void UnknownOrMissingStatusOrInsufficientCertificationIsDenied()
    {
        var blob = Blob();
        blob.Entries[0].StatusReports = [];
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob.Entries[0].StatusReports = [new StatusReport { Status = (AuthenticatorStatus)999 }];
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob.Entries[0].StatusReports =
            [new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED_L1 }];
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob.Entries[0].StatusReports =
            [new StatusReport { Status = AuthenticatorStatus.FIDO_CERTIFIED_L2plus }];
        Assert.Equal("UNAPPROVED", Inspect(blob).ReviewStatus);
    }

    [Fact]
    public void AaguidMustBePresentUniqueAndMatchMetadataStatement()
    {
        var blob = Blob();
        blob.Entries = [];
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob = Blob();
        blob.Entries[0].AaGuid = Guid.NewGuid();
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob = Blob();
        blob.Entries[0].MetadataStatement.AaGuid = Guid.NewGuid();
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob = Blob();
        blob.Entries = [blob.Entries[0], blob.Entries[0]];
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
    }

    [Fact]
    public void AttestationRootsMustExistBeBoundedAndHaveValidDer()
    {
        var blob = Blob();
        blob.Entries[0].MetadataStatement.AttestationRootCertificates = [];
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob.Entries[0].MetadataStatement.AttestationRootCertificates = ["not-base64"];
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob.Entries[0].MetadataStatement.AttestationRootCertificates =
            [Convert.ToBase64String([1, 2, 3])];
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob.Entries[0].MetadataStatement.AttestationRootCertificates =
            Enumerable.Repeat(TestAnchor(), 9).ToArray();
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
    }

    [Fact]
    public void UnsupportedProtocolAttestationOrRogueListDenies()
    {
        var blob = Blob();
        blob.Entries[0].MetadataStatement.ProtocolFamily = "u2f";
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob = Blob();
        blob.Entries[0].MetadataStatement.Schema = 4;
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob = Blob();
        blob.Entries[0].MetadataStatement.AttestationTypes = ["none"];
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob = Blob();
        blob.Entries[0].RogueListURL = "https://example.org/rogue";
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
    }

    [Fact]
    public void SerialRollbackStaleOrFutureObservationAndExpiredNextUpdateDeny()
    {
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(minimumSerial: 43));
        Assert.Throws<UnauthorizedAccessException>(() =>
            Inspect(observed: Now.AddHours(-25)));
        Assert.Throws<UnauthorizedAccessException>(() =>
            Inspect(observed: Now.AddSeconds(1)));
        var blob = Blob();
        blob.Number = 0;
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob = Blob();
        blob.NextUpdate = "2026-11-14";
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob.NextUpdate = "bogus";
        Assert.Throws<UnauthorizedAccessException>(() => Inspect(blob));
        blob.NextUpdate = ""; // MDS 3.1.1 discourages reliance on this field.
        Assert.Equal("UNAPPROVED", Inspect(blob).ReviewStatus);
    }

    [Fact]
    public void NoMetadataPolicyCheckCanUpgradeCandidateOrSyncedPasskey()
    {
        foreach (var candidate in new[]
        {
            Candidate(status: "ACTIVE"),
            Candidate(type: "self"),
            Candidate(format: "none"),
            Candidate(aaguid: Guid.Empty),
            Candidate(backupEligible: true),
            Candidate(backedUp: true),
            Candidate() with { CredentialIdSha256 = "zzzz" }
        })
            Assert.Throws<UnauthorizedAccessException>(() => Inspect(candidate: candidate));
    }
}
