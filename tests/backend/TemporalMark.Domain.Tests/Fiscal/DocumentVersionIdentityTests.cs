using TemporalMark.Domain.Documents;
using Xunit;

namespace TemporalMark.Domain.Tests.Fiscal;

public sealed class DocumentVersionIdentityTests
{
    private static readonly Guid Tenant = Guid.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly Guid Document = Guid.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly Guid Version = Guid.Parse("33333333-3333-4333-8333-333333333333");
    private static readonly DateTimeOffset Acquired = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
    private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    [Fact]
    public void DefaultSourceClassIsUnknown()
    {
        Assert.Equal(DocumentSourceClass.Unknown, default(DocumentSourceClass));
    }

    [Theory]
    [InlineData(DocumentSourceClass.Unknown)]
    [InlineData(DocumentSourceClass.NativeDigital)]
    [InlineData(DocumentSourceClass.AnalogNonUnique)]
    [InlineData(DocumentSourceClass.AnalogUnique)]
    [InlineData(DocumentSourceClass.Excluded)]
    public void SourceAssertionDoesNotAuthorizeDisposal(DocumentSourceClass source)
    {
        var identity = new DocumentVersionIdentity(Tenant, Document, Version, Hash, 42, Acquired, source);
        Assert.Equal(source, identity.SourceClass);
        Assert.False(identity.PaperDisposalEligible);
    }

    [Fact]
    public void SeparateVersionCannotMutateExistingIdentity()
    {
        var original = new DocumentVersionIdentity(Tenant, Document, Version, Hash, 42, Acquired,
            DocumentSourceClass.Unknown);
        var anotherId = Guid.Parse("44444444-4444-4444-8444-444444444444");
        var anotherHash = new string('a', 64);
        var other = new DocumentVersionIdentity(Tenant, Document, anotherId, anotherHash, 43,
            Acquired.AddSeconds(1), DocumentSourceClass.NativeDigital);
        Assert.Equal(Version, original.VersionId);
        Assert.Equal(Hash, original.Sha256Hex);
        Assert.Equal(42L, original.ByteLength);
        Assert.Equal(DocumentSourceClass.Unknown, original.SourceClass);
        Assert.Equal(anotherId, other.VersionId);
        Assert.Equal(anotherHash, other.Sha256Hex);
        Assert.False(original.PaperDisposalEligible);
        Assert.False(other.PaperDisposalEligible);
    }

    [Fact]
    public void CrossTenantAccessIsDeniedWithoutDisclosingOwner()
    {
        var identity = new DocumentVersionIdentity(Tenant, Document, Version, Hash, 42, Acquired,
            DocumentSourceClass.Unknown);
        identity.RequireTenant(Tenant);
        var denial = Assert.Throws<ArgumentException>(() => identity.RequireTenant(Document));
        Assert.DoesNotContain(Tenant.ToString(), denial.Message);
        Assert.Throws<ArgumentException>(() => identity.RequireTenant(Guid.Empty));
    }

    [Theory]
    [InlineData(' ')]
    [InlineData('\n')]
    [InlineData('Ａ')]
    [InlineData('０')]
    public void RejectsNonAsciiOrWhitespaceInDigest(char character)
    {
        var malformed = character + Hash[1..];
        Assert.Throws<ArgumentException>(() => new DocumentVersionIdentity(
            Tenant, Document, Version, malformed, 42, Acquired, DocumentSourceClass.Unknown));
    }
}
