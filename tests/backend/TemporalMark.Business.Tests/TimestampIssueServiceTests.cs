using System.Security.Cryptography;
using TemporalMark.Business.Stamping;
using TemporalMark.Domain.Stamping;
using Xunit;

namespace TemporalMark.Business.Tests;

public sealed class TimestampIssueServiceTests
{
    private static readonly Guid Organization = Guid.Parse("11111111-1111-1111-1111-111111111111");

    [Theory]
    [InlineData("")]
    [InlineData("invalidBase64!")]
    [InlineData("AQID")]
    public async Task RejectsInvalidImprintBeforeCallingProvider(string digestBase64)
    {
        var provider = new FakeProvider();
        var writer = new FakeWriter();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new TimestampIssueService(provider, writer).IssueAsync(Organization, digestBase64, default));
        Assert.Equal(0, provider.Requests);
        Assert.Null(writer.Record);
    }

    [Theory]
    [InlineData("leading-whitespace")]
    [InlineData("trailing-whitespace")]
    [InlineData("embedded-space")]
    [InlineData("embedded-tab")]
    [InlineData("embedded-crlf")]
    [InlineData("no-padding")]
    [InlineData("extra-padding")]
    [InlineData("nonzero-pad-bits")]
    [InlineData("urlsafe-alphabet")]
    [InlineData("invalid-char")]
    public async Task NonCanonicalSha256TextIsDeniedWithoutTsaOrPersistence(string mutation)
    {
        // RED-first: .NET Convert.FromBase64String tolerates whitespace and
        // some text aliases of the same digest. The API accepts ONE encoding.
        var canonical = Convert.ToBase64String(new byte[32]);
        var untrusted = mutation switch
        {
            "leading-whitespace" => " " + canonical,
            "trailing-whitespace" => canonical + "\n",
            "embedded-space" => canonical.Insert(4, " "),
            "embedded-tab" => canonical.Insert(12, "\t"),
            "embedded-crlf" => canonical.Insert(16, "\r\n"),
            "no-padding" => canonical.TrimEnd('='),
            "extra-padding" => canonical + "=",
            // A 32-byte digest ends with 2 real bits in its last Base64
            // character. Changing its unused low bits is not canonical.
            "nonzero-pad-bits" => canonical[..42] + "B=",
            "urlsafe-alphabet" => Convert.ToBase64String(
                Enumerable.Repeat((byte)255, 32).ToArray()).Replace('/', '_'),
            "invalid-char" => canonical[..7] + "!" + canonical[8..],
            _ => throw new InvalidOperationException("Unrecognized test mutation.")
        };
        var provider = new FakeProvider();
        var writer = new FakeWriter();

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            new TimestampIssueService(provider, writer).IssueAsync(
                Organization, untrusted, CancellationToken.None));

        Assert.Equal(0, provider.Requests);
        Assert.Null(writer.Record);
        Assert.DoesNotContain(untrusted, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task OversizedImprintTextIsDeniedBeforeProviderOrStorage()
    {
        // Deliberately much larger than 44 characters: no unbounded
        // Convert.FromBase64String allocation should ever be attempted.
        var oversized = new string('A', 1_000_000);
        var provider = new FakeProvider();
        var writer = new FakeWriter();

        var error = await Assert.ThrowsAsync<ArgumentException>(() =>
            new TimestampIssueService(provider, writer).IssueAsync(
                Organization, oversized, CancellationToken.None));

        Assert.Equal(0, provider.Requests);
        Assert.Null(writer.Record);
        Assert.True(error.Message.Length < 256);
    }

    [Fact]
    public async Task CanonicalAllZeroSha256IsStillForwardedExactlyOnce()
    {
        var provider = new FakeProvider();
        var writer = new FakeWriter();
        var digest = new byte[32];

        var record = await new TimestampIssueService(provider, writer).IssueAsync(
            Organization, Convert.ToBase64String(digest), CancellationToken.None);

        Assert.Equal(1, provider.Requests);
        Assert.Equal(digest, provider.LastDigest);
        Assert.Equal(Convert.ToBase64String(digest), record.DigestBase64);
        Assert.Equal(TimestampValidationState.Unverified, writer.Record!.ValidationState);
    }

    [Fact]
    public async Task ValidImprintPersistsOriginalResponseButNeverClaimsQualification()
    {
        var provider = new FakeProvider();
        var writer = new FakeWriter();
        var imprint = SHA256.HashData("private document content"u8.ToArray());
        var record = await new TimestampIssueService(provider, writer).IssueAsync(
            Organization, Convert.ToBase64String(imprint), default);
        Assert.Equal(1, provider.Requests);
        Assert.Equal(Organization, record.OrganizationId);
        Assert.Equal(TimestampValidationState.Unverified, record.ValidationState);
        Assert.Equal(Convert.ToBase64String(imprint), record.DigestBase64);
        Assert.Equal("2.16.840.1.101.3.4.2.1", record.HashAlgorithmOid);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(provider.RawResponse)), record.TokenSha256Hex);
        Assert.Equal(provider.RawResponse, writer.Record!.ResponseDer);
        Assert.Equal(record, writer.Record);
    }

    // #178 / ADR 0136: provider identifiers and policies are source
    // metadata, never evidence of current EU Trusted List qualification.
    // ProviderTimestamp has no authority to supply a validation state.
    [Fact]
    public async Task ProviderQualificationClaimCannotElevatePilotIssuanceState()
    {
        var provider = new ScriptedProvider(
            [0x30, 0x02, 0x01, 0x00],
            "1.2.3.4", "VerifiedQualifiedExternal");
        var writer = new FakeWriter();

        var issued = await new TimestampIssueService(provider, writer).IssueAsync(
            Organization, Convert.ToBase64String(new byte[32]), default);

        Assert.Equal(1, provider.Requests);
        Assert.Equal("VerifiedQualifiedExternal", issued.ProviderId);
        Assert.Equal(TimestampValidationState.Unverified, issued.ValidationState);
        Assert.Equal(TimestampValidationState.Unverified, writer.Record!.ValidationState);
        Assert.Equal(issued, writer.Record);
    }

    [Fact]
    public async Task RejectsEmptyOrganization()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new TimestampIssueService(new FakeProvider(), new FakeWriter()).IssueAsync(
                Guid.Empty, Convert.ToBase64String(new byte[32]), default));
    }

    // #177 / ADR 0135: new issued records must fit already-enforced
    // registry read budgets, even with an alternate/malformed provider.
    // Every negative is AFTER exactly one request but BEFORE any writer.
    [Theory]
    [InlineData("over-provider")]
    [InlineData("over-policy")]
    [InlineData("unicode-provider")]
    [InlineData("over-der")]
    [InlineData("empty-policy")]
    [InlineData("blank-provider")]
    public async Task ProviderResponsesOutsidePilotRegistryWriteBudgetDoNotPersist(
        string variant)
    {
        var ordinaryDer = new byte[] { 0x30, 0x02, 0x01, 0x00 };
        var bytes = variant == "over-der"
            ? new byte[1024 * 1024 + 1]
            : ordinaryDer;
        var policy = variant switch
        {
            "over-policy" => new string('P', 16 * 1024 + 1),
            "empty-policy" => "",
            _ => "1.2.3.4"
        };
        var providerName = variant switch
        {
            "over-provider" => new string('R', 16 * 1024 + 1),
            // Only 8193 UTF-16 chars but 16386 actual UTF8 bytes.
            "unicode-provider" => new string('é', 16 * 1024 / 2 + 1),
            "blank-provider" => "  ",
            _ => "ci-operator-approved-provider"
        };
        var provider = new ScriptedProvider(bytes, policy, providerName);
        var writer = new FakeWriter();
        var canonicalSha256 = Convert.ToBase64String(new byte[32]);

        var error = await Assert.ThrowsAsync<TimestampProviderResponseException>(() =>
            new TimestampIssueService(provider, writer).IssueAsync(
                Organization, canonicalSha256, default));

        Assert.Equal(1, provider.Requests);
        Assert.Null(writer.Record);
        Assert.Equal("External TSA response exceeds pilot registry persistence limits.",
            error.Message);
        Assert.DoesNotContain(Organization.ToString(), error.ToString());
        Assert.DoesNotContain(canonicalSha256, error.ToString());
        Assert.DoesNotContain(providerName[..Math.Min(16, providerName.Length)],
            error.Message);
    }

    [Fact]
    public async Task PilotIssuanceRetainsOriginalExactlyBoundedProviderFieldsAndDer()
    {
        const int metadataLimit = 16 * 1024;
        const int derLimit = 1024 * 1024;
        var der = new byte[derLimit];
        der[0] = 0x30;
        der[^1] = 0x01;
        var providerId = new string('Q', metadataLimit);
        var policy = new string('7', metadataLimit);
        var provider = new ScriptedProvider(der, policy, providerId);
        var writer = new FakeWriter();

        var record = await new TimestampIssueService(provider, writer).IssueAsync(
            Organization, Convert.ToBase64String(new byte[32]), default);

        Assert.Equal(1, provider.Requests);
        Assert.Equal(providerId, record.ProviderId);
        Assert.Equal(policy, record.PolicyOid);
        Assert.Equal(der, writer.Record!.ResponseDer);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(der)), record.TokenSha256Hex);
        Assert.Equal(TimestampValidationState.Unverified, record.ValidationState);
        Assert.Equal(TimeSpan.Zero, record.IssuedUtc.Offset);
        Assert.Equal(record, writer.Record);
    }

    private sealed class ScriptedProvider(
        byte[] rawDer, string policyOid, string providerId) : ITimestampProvider
    {
        public int Requests { get; private set; }
        public Task<ProviderTimestamp> RequestAsync(byte[] sha256Digest, CancellationToken ct)
        {
            Requests++;
            return Task.FromResult(new ProviderTimestamp(
                rawDer, new DateTimeOffset(2026, 11, 15, 10, 0, 0, TimeSpan.Zero),
                policyOid, providerId));
        }
    }

    private sealed class FakeProvider : ITimestampProvider
    {
        public int Requests { get; private set; }
        public byte[]? LastDigest { get; private set; }
        public byte[] RawResponse { get; } = [0x30, 0x02, 0x01, 0x00];
        public Task<ProviderTimestamp> RequestAsync(byte[] sha256Digest, CancellationToken ct)
        {
            Requests++;
            LastDigest = sha256Digest.ToArray();
            return Task.FromResult(new ProviderTimestamp(RawResponse, new DateTimeOffset(2026, 11, 15, 10, 0, 0, TimeSpan.Zero),
                "1.2.3.4", "configured-test-provider"));
        }
    }

    private sealed class FakeWriter : ITimestampWriter
    {
        public TimestampRecord? Record { get; private set; }
        public Task AppendAsync(TimestampRecord record, CancellationToken ct)
        {
            Record = record;
            return Task.CompletedTask;
        }
    }
}
