using System.Reflection;
using TemporalMark.Domain.Stamping;
using Xunit;

namespace TemporalMark.Domain.Tests.Fiscal;

// Initial test-only contract: an absent implementation fails a test rather
// than breaking compilation. Replace with strongly typed tests after RED.
public sealed class DocumentVersionIdentityContractTests
{
    private static readonly Assembly Domain = typeof(UtcPeriod).Assembly;
    private static readonly Guid Tenant = Guid.Parse("11111111-1111-4111-8111-111111111111");
    private static readonly Guid Document = Guid.Parse("22222222-2222-4222-8222-222222222222");
    private static readonly Guid Version = Guid.Parse("33333333-3333-4333-8333-333333333333");
    private static readonly DateTimeOffset Acquired = new(2026, 11, 1, 0, 0, 0, TimeSpan.Zero);
    private const string Hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    private static Type RequiredType(string name)
    {
        var type = Domain.GetType("TemporalMark.Domain.Documents." + name);
        Assert.NotNull(type);
        return type!;
    }

    private static object Create(Guid tenant, Guid document, Guid version, string? hash,
        long length, DateTimeOffset acquired, string source = "Unknown", int? invalidSource = null)
    {
        var type = RequiredType("DocumentVersionIdentity");
        var sourceType = RequiredType("DocumentSourceClass");
        var value = invalidSource.HasValue
            ? Enum.ToObject(sourceType, invalidSource.Value)
            : Enum.Parse(sourceType, source);
        var constructor = type.GetConstructor(new[] { typeof(Guid), typeof(Guid), typeof(Guid),
            typeof(string), typeof(long), typeof(DateTimeOffset), sourceType });
        Assert.NotNull(constructor);
        return constructor!.Invoke(new object?[] { tenant, document, version, hash, length, acquired, value });
    }

    private static object Valid(string source = "Unknown") =>
        Create(Tenant, Document, Version, Hash, 42, Acquired, source);

    private static object? Read(object instance, string property)
    {
        var info = instance.GetType().GetProperty(property);
        Assert.NotNull(info);
        Assert.False(info!.SetMethod?.IsPublic ?? false);
        return info.GetValue(instance);
    }

    private static void Reject(Action action)
    {
        var failure = Assert.Throws<TargetInvocationException>(action);
        Assert.IsAssignableFrom<ArgumentException>(failure.InnerException);
    }

    [Theory]
    [InlineData("Unknown")]
    [InlineData("NativeDigital")]
    [InlineData("AnalogNonUnique")]
    [InlineData("AnalogUnique")]
    [InlineData("Excluded")]
    public void StoresImmutableIdentityButNeverGrantsPaperDisposal(string source)
    {
        var instance = Valid(source);
        Assert.Equal(Tenant, Assert.IsType<Guid>(Read(instance, "OrganizationId")));
        Assert.Equal(Document, Assert.IsType<Guid>(Read(instance, "DocumentId")));
        Assert.Equal(Version, Assert.IsType<Guid>(Read(instance, "VersionId")));
        Assert.Equal(Hash, Assert.IsType<string>(Read(instance, "Sha256Hex")));
        Assert.Equal(42L, Assert.IsType<long>(Read(instance, "ByteLength")));
        Assert.Equal(Acquired, Assert.IsType<DateTimeOffset>(Read(instance, "AcquiredUtc")));
        Assert.Equal(source, Read(instance, "SourceClass")?.ToString());
        Assert.False(Assert.IsType<bool>(Read(instance, "PaperDisposalEligible")));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    public void RejectsEmptyIdentity(int index)
    {
        var ids = new[] { Tenant, Document, Version };
        ids[index] = Guid.Empty;
        Reject(() => Create(ids[0], ids[1], ids[2], Hash, 42, Acquired));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("short")]
    [InlineData("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")]
    [InlineData("g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")]
    public void RejectsNonCanonicalHash(string? hash) =>
        Reject(() => Create(Tenant, Document, Version, hash, 42, Acquired));

    [Theory]
    [InlineData(0L)]
    [InlineData(-1L)]
    public void RejectsNonPositiveLength(long length) =>
        Reject(() => Create(Tenant, Document, Version, Hash, length, Acquired));

    [Fact]
    public void RejectsNonUtcAcquisitionTime() =>
        Reject(() => Create(Tenant, Document, Version, Hash, 42, Acquired.ToOffset(TimeSpan.FromHours(1))));

    [Fact]
    public void RejectsUndefinedSourceClass() =>
        Reject(() => Create(Tenant, Document, Version, Hash, 42, Acquired, invalidSource: 999));

    [Fact]
    public void RequiresMatchingAuthorizedTenant()
    {
        var instance = Valid();
        var method = instance.GetType().GetMethod("RequireTenant", new[] { typeof(Guid) });
        Assert.NotNull(method);
        method!.Invoke(instance, new object[] { Tenant });
        Reject(() => method.Invoke(instance, new object[] { Document }));
        Reject(() => method.Invoke(instance, new object[] { Guid.Empty }));
    }
}
