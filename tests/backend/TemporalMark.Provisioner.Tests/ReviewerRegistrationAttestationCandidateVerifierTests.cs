using System.Security.Cryptography;
using System.Text;
using Fido2NetLib;
using Fido2NetLib.Objects;
using TemporalMark.Business.Tenancy;
using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// Test-first isolated Fido2 4.3.3 adapter. Fake successful material only
/// tests post-verifier quarantine; it is NOT an actual browser attestation.
/// Real library rejects an invalid/fabricated WebAuthn attestation.
/// </summary>
public sealed class ReviewerRegistrationAttestationCandidateVerifierTests
{
    private const string Rp = "review.example.org";
    private const string Origin = "https://review.example.org";
    private const string Issuer = "https://identity.example.org/realms/review";
    private static readonly byte[] CredentialId = Enumerable.Repeat((byte)0x19, 32).ToArray();

    private static CredentialCreateOptions Options() => new()
    {
        Rp = new PublicKeyCredentialRpEntity(Rp, "TemporalMark Review"),
        User = new Fido2User
        {
            Name = "reviewer", DisplayName = "Independent reviewer",
            Id = Enumerable.Repeat((byte)0x65, 32).ToArray()
        },
        Challenge = Enumerable.Repeat((byte)0x42, 48).ToArray(),
        PubKeyCredParams = PubKeyCredParam.Defaults,
        Attestation = AttestationConveyancePreference.Direct,
        AuthenticatorSelection = new AuthenticatorSelection
        {
            UserVerification = UserVerificationRequirement.Required
        }
    };

    private static ReviewerRegistrationAttestationCeremony Ceremony(
        CredentialCreateOptions options) => new(
        Issuer, "reviewer-sub", "independent-registrar-sub",
        options.Challenge.ToArray(), options.User.Id.ToArray(),
        DateTimeOffset.UtcNow.AddSeconds(-10),
        DateTimeOffset.UtcNow.AddSeconds(70));

    private static AuthenticatorAttestationRawResponse Raw() => new()
    {
        Id = Convert.ToBase64String(CredentialId).TrimEnd('=').Replace('+', '-').Replace('/', '_'),
        RawId = CredentialId.ToArray(),
        Type = PublicKeyCredentialType.PublicKey,
        ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
        Response = new AuthenticatorAttestationRawResponse.AttestationResponse
        {
            AttestationObject = [0xA1, 0x00, 0x01, 0x02],
            ClientDataJson = Encoding.UTF8.GetBytes(
                "{\"type\":\"webauthn.create\",\"challenge\":\"bogus\",\"origin\":\"https://review.example.org\"}")
        }
    };

    private static RegisteredPublicKeyCredential Credential(CredentialCreateOptions options,
        string attestationType = "basic") => new()
    {
        Id = CredentialId.ToArray(),
        User = options.User,
        PublicKey = Enumerable.Repeat((byte)0x38, 77).ToArray(),
        AttestationType = attestationType,
        AttestationFormat = "packed",
        AaGuid = Guid.Parse("00000000-0000-4000-8000-000000000045"),
        SignCount = 0,
        IsBackupEligible = false,
        IsBackedUp = false
    };

    private static IsCredentialIdUniqueToUserAsyncDelegate Unique =>
        (args, ct) => Task.FromResult(true); // Test stub ONLY; NOT actual global registry.
    private static ReviewerRegistrationAttestationCandidateVerifier Make(RecordingFido2 fido) =>
        new(fido, new ReviewerWebAuthnRelyingPartyPolicy(Rp, Origin));

    [Fact]
    public async Task LibraryResultIsOnlyUnapprovedHashMetadataNeverPublicKeyOrActiveCredential()
    {
        var options = Options();
        var fido = new RecordingFido2 { Result = Credential(options) };
        var candidate = await Make(fido).VerifyCandidateAsync(Ceremony(options), options, Raw(), Unique);
        Assert.Equal(1, fido.Calls);
        Assert.Equal("UNAPPROVED", candidate.ReviewStatus);
        Assert.Equal(Issuer, candidate.IdentityIssuer);
        Assert.Equal("reviewer-sub", candidate.ReviewerSubject);
        Assert.Equal("independent-registrar-sub", candidate.RegistrarSubject);
        Assert.Equal(Rp, candidate.RelyingPartyId);
        Assert.Equal("basic", candidate.AttestationType);
        Assert.Equal("packed", candidate.AttestationFormat);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(CredentialId)),
            candidate.CredentialIdSha256);
        Assert.Equal(64, candidate.PublicKeySha256.Length);
        Assert.DoesNotContain("PublicKey", typeof(ReviewerAttestationReviewCandidate)
            .GetProperties().Select(p => p.Name).Where(p => p != "PublicKeySha256"));
        Assert.NotNull(fido.LastParams?.IsCredentialIdUniqueToUserCallback);
        Assert.Equal(options, fido.LastParams?.OriginalOptions);
    }

    [Fact]
    public async Task OriginalServerChallengeMustBeExact48BytesAndNeverBrowserSelected()
    {
        var options = Options();
        var fido = new RecordingFido2 { Result = Credential(options) };
        var valid = Ceremony(options);
        foreach (var bad in new[]
        {
            valid with { ExpectedChallenge = new byte[47] },
            valid with { ExpectedChallenge = new byte[48] },
            valid with { ExpectedChallenge = new byte[49] }
        })
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                Make(fido).VerifyCandidateAsync(bad, options, Raw(), Unique));
        Assert.Equal(0, fido.Calls);
    }

    [Fact]
    public async Task WrongRpUserHandleWeakUvOrNoAttestationNeverCallsLibrary()
    {
        var options = Options();
        var fido = new RecordingFido2 { Result = Credential(options) };
        var scope = Ceremony(options);
        options.Rp.Id = "malicious.example.org";
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Make(fido).VerifyCandidateAsync(scope, options, Raw(), Unique));
        options.Rp.Id = Rp;

        options.User.Id = new byte[32];
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Make(fido).VerifyCandidateAsync(scope, options, Raw(), Unique));
        options.User.Id = scope.ExpectedUserHandle.ToArray();

        options.Attestation = AttestationConveyancePreference.None;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Make(fido).VerifyCandidateAsync(scope, options, Raw(), Unique));
        options.Attestation = AttestationConveyancePreference.Direct;

        options.AuthenticatorSelection!.UserVerification = UserVerificationRequirement.Preferred;
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Make(fido).VerifyCandidateAsync(scope, options, Raw(), Unique));
        Assert.Equal(0, fido.Calls);
    }

    [Fact]
    public async Task ReusedExpiredFutureOrSelfRegistrarScopeNeverCallsVerifier()
    {
        var options = Options();
        var fido = new RecordingFido2 { Result = Credential(options) };
        var scope = Ceremony(options);
        foreach (var bad in new[]
        {
            scope with { RegistrarSubject = scope.ReviewerSubject },
            scope with { ReviewerSubject = "" },
            scope with { ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(-1) },
            scope with { IssuedUtc = DateTimeOffset.UtcNow.AddMinutes(4) },
            scope with { ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(4) },
            scope with { ExpectedUserHandle = new byte[12] }
        })
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                Make(fido).VerifyCandidateAsync(bad, options, Raw(), Unique));
        Assert.Equal(0, fido.Calls);
    }

    [Fact]
    public async Task MissingMalformedOrHugeBrowserAttestationDoesNotReachLibrary()
    {
        var options = Options();
        var fido = new RecordingFido2 { Result = Credential(options) };
        var scope = Ceremony(options);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Make(fido).VerifyCandidateAsync(scope, options, null, Unique));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Make(fido).VerifyCandidateAsync(scope, options, withMalformedId(), Unique));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Make(fido).VerifyCandidateAsync(scope, options, withHugeAttestation(), Unique));
        Assert.Equal(0, fido.Calls);
    }

    private static AuthenticatorAttestationRawResponse withMalformedId()
    {
        var value = Raw();
        return new AuthenticatorAttestationRawResponse
        {
            Id = "not-the-raw-id", RawId = value.RawId,
            Type = PublicKeyCredentialType.PublicKey, Response = value.Response,
            ClientExtensionResults = value.ClientExtensionResults
        };
    }

    private static AuthenticatorAttestationRawResponse withHugeAttestation()
    {
        var value = Raw();
        return new AuthenticatorAttestationRawResponse
        {
            Id = value.Id, RawId = value.RawId, Type = value.Type,
            ClientExtensionResults = value.ClientExtensionResults,
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                AttestationObject = new byte[131073],
                ClientDataJson = value.Response.ClientDataJson
            }
        };
    }

    [Theory]
    [InlineData("none")]
    [InlineData("self")]
    [InlineData("unknown")]
    public async Task NoneSelfOrUnknownAttestationTypeCanNeverBecomeTrustedCandidate(string attestationType)
    {
        var options = Options();
        var fido = new RecordingFido2 { Result = Credential(options, attestationType) };
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            Make(fido).VerifyCandidateAsync(Ceremony(options), options, Raw(), Unique));
        Assert.Equal(1, fido.Calls);
    }

    [Fact]
    public async Task LibraryOutputWrongCredentialOrRpOrUserHandleCannotBeReturned()
    {
        var options = Options();
        var original = Credential(options);
        var cases = new[]
        {
            new RegisteredPublicKeyCredential
            {
                Id = new byte[32], User = options.User,
                PublicKey = original.PublicKey, AttestationType = "basic", AttestationFormat = "packed"
            },
            new RegisteredPublicKeyCredential
            {
                Id = CredentialId,
                User = new Fido2User { Id = new byte[32], Name = "wrong", DisplayName = "wrong" },
                PublicKey = original.PublicKey, AttestationType = "basic", AttestationFormat = "packed"
            }
        };
        var fido = new RecordingFido2();
        foreach (var bad in cases)
        {
            fido.Result = bad;
            await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
                Make(fido).VerifyCandidateAsync(Ceremony(options), options, Raw(), Unique));
        }
        Assert.Equal(2, fido.Calls);
    }

    [Fact]
    public async Task RealMaintainedFido2MustRejectBogusClientDataAndAttestation()
    {
        var options = Options();
        var verifier = new ReviewerRegistrationAttestationCandidateVerifier(
            new Fido2(new Fido2Configuration
            {
                RPID = Rp, RPName = "TemporalMark", ChallengeSize = 48,
                Origins = new HashSet<string> { Origin }
            }), new ReviewerWebAuthnRelyingPartyPolicy(Rp, Origin));

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            verifier.VerifyCandidateAsync(Ceremony(options), options, Raw(), Unique));
    }

    private sealed class RecordingFido2 : IFido2
    {
        public RegisteredPublicKeyCredential? Result { get; set; }
        public int Calls { get; private set; }
        public MakeNewCredentialParams? LastParams { get; private set; }

        public Task<RegisteredPublicKeyCredential> MakeNewCredentialAsync(
            MakeNewCredentialParams args, CancellationToken cancellationToken = default)
        {
            Calls++;
            LastParams = args;
            return Task.FromResult(Result!);
        }
        public CredentialCreateOptions RequestNewCredential(RequestNewCredentialParams args) =>
            throw new NotSupportedException();
        public AssertionOptions GetAssertionOptions(GetAssertionOptionsParams args) =>
            throw new NotSupportedException();
        public Task<VerifyAssertionResult> MakeAssertionAsync(MakeAssertionParams args,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();

    }
}
