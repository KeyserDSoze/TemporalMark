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
        public byte[] RawResponse { get; } = [0x30, 0x02, 0x01, 0x00];
        public Task<ProviderTimestamp> RequestAsync(byte[] sha256Digest, CancellationToken ct)
        {
            Requests++;
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
