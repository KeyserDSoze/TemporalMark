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

    [Fact]
    public async Task RejectsEmptyOrganization()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            new TimestampIssueService(new FakeProvider(), new FakeWriter()).IssueAsync(
                Guid.Empty, Convert.ToBase64String(new byte[32]), default));
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
