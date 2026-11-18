using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first #97: KU and Basic Constraints of the independently verified
/// TSA CMS signer. Ephemeral certificates are not QTSP trust evidence.
/// </summary>
public sealed class ExternalRfc3161TsaLeafProfilePolicyTests
{
    private const string KeyUsageOid = "2.5.29.15";
    private const string BasicConstraintsOid = "2.5.29.19";

    [Theory]
    [InlineData(X509KeyUsageFlags.DigitalSignature)]
    [InlineData(X509KeyUsageFlags.NonRepudiation)]
    [InlineData(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation)]
    public void SigningOnlyNonCaCertificatePasses(X509KeyUsageFlags flags)
    {
        using var signer = CreateCertificate(false, flags);
        ExternalRfc3161TsaLeafProfilePolicy.Validate(signer);
    }

    [Fact]
    public void MissingCertificateIsDenied()
    {
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161TsaLeafProfilePolicy.Validate(null));
    }

    [Fact]
    public void CaCertificateWithSigningUsageIsDenied()
    {
        using var signer = CreateCertificate(true, X509KeyUsageFlags.DigitalSignature);
        AssertRejected(signer);
    }

    [Fact]
    public void MissingBasicConstraintsIsDeniedByExplicitPilotProfile()
    {
        using var signer = CreateCertificate(null, X509KeyUsageFlags.DigitalSignature);
        AssertRejected(signer);
    }

    [Fact]
    public void MissingKeyUsageIsDenied()
    {
        using var signer = CreateCertificate(false, null);
        AssertRejected(signer);
    }

    [Theory]
    [InlineData(X509KeyUsageFlags.KeyEncipherment)]
    [InlineData(X509KeyUsageFlags.KeyCertSign)]
    [InlineData(X509KeyUsageFlags.CrlSign)]
    [InlineData(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign)]
    [InlineData(X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.CrlSign)]
    [InlineData(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment)]
    [InlineData(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyAgreement)]
    public void NonSigningOrSharedUseBitsAreDenied(X509KeyUsageFlags flags)
    {
        using var signer = CreateCertificate(false, flags);
        AssertRejected(signer);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void MalformedCertificateExtensionsAreDenied(bool malformedBasicConstraints, bool malformedKeyUsage)
    {
        using var signer = CreateCertificate(false, X509KeyUsageFlags.DigitalSignature,
            malformedBasicConstraints, malformedKeyUsage);
        AssertRejected(signer);
    }

    [Theory]
    [InlineData(KeyUsageOid)]
    [InlineData(BasicConstraintsOid)]
    public void DuplicateExtensionIsDeniedEvenIfEachCopyLooksValid(string oid)
    {
        using var valid = CreateCertificate(false, X509KeyUsageFlags.DigitalSignature);
        using var duplicate = DuplicateExtensionInSyntheticCertificate(valid, oid);
        // Deliberately no signature verification: these synthetic bytes
        // exercise the extension parser only, NOT PKIX acceptance.
        AssertRejected(duplicate);
    }

    private static void AssertRejected(X509Certificate2 signer)
    {
        var error = Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161TsaLeafProfilePolicy.Validate(signer));
        Assert.Contains("signer", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static X509Certificate2 CreateCertificate(
        bool? isCa, X509KeyUsageFlags? keyUsage,
        bool malformedBasicConstraints = false, bool malformedKeyUsage = false)
    {
        using var key = RSA.Create(2048);
        var req = new CertificateRequest("CN=Disposable TSA signer usage profile",
            key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        if (isCa.HasValue)
            req.CertificateExtensions.Add(malformedBasicConstraints
                ? new X509Extension(new Oid(BasicConstraintsOid), new byte[] { 0x05, 0x00 }, false)
                : new X509BasicConstraintsExtension(isCa.Value, false, 0, false));

        if (keyUsage.HasValue)
            req.CertificateExtensions.Add(malformedKeyUsage
                ? new X509Extension(new Oid(KeyUsageOid), new byte[] { 0x05, 0x00 }, true)
                : new X509KeyUsageExtension(keyUsage.Value, true));

        return req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static X509Certificate2 DuplicateExtensionInSyntheticCertificate(
        X509Certificate2 original, string duplicateOid)
    {
        var outer = new AsnReader(original.RawData, AsnEncodingRules.DER).ReadSequence();
        var tbsDer = outer.ReadEncodedValue();
        var algorithm = outer.ReadEncodedValue();
        var signature = outer.ReadEncodedValue();

        var tbs = new AsnReader(tbsDer, AsnEncodingRules.DER).ReadSequence();
        var fields = new List<ReadOnlyMemory<byte>>();
        while (tbs.HasData)
            fields.Add(tbs.ReadEncodedValue());

        var tag = new Asn1Tag(TagClass.ContextSpecific, 3, isConstructed: true);
        var container = new AsnReader(fields[^1], AsnEncodingRules.DER).ReadSequence(tag);
        var extensions = container.ReadSequence();
        var encoded = new List<ReadOnlyMemory<byte>>();
        while (extensions.HasData)
            encoded.Add(extensions.ReadEncodedValue());

        var target = encoded.Single(value =>
            new AsnReader(value, AsnEncodingRules.DER).ReadSequence()
                .ReadObjectIdentifier() == duplicateOid);

        var extensionWriter = new AsnWriter(AsnEncodingRules.DER);
        extensionWriter.PushSequence(tag);
        extensionWriter.PushSequence();
        foreach (var item in encoded)
            extensionWriter.WriteEncodedValue(item.Span);
        extensionWriter.WriteEncodedValue(target.Span);
        extensionWriter.PopSequence();
        extensionWriter.PopSequence(tag);

        var newTbs = new AsnWriter(AsnEncodingRules.DER);
        newTbs.PushSequence();
        foreach (var field in fields.Take(fields.Count - 1))
            newTbs.WriteEncodedValue(field.Span);
        newTbs.WriteEncodedValue(extensionWriter.Encode());
        newTbs.PopSequence();

        var output = new AsnWriter(AsnEncodingRules.DER);
        output.PushSequence();
        output.WriteEncodedValue(newTbs.Encode());
        output.WriteEncodedValue(algorithm.Span);
        output.WriteEncodedValue(signature.Span);
        output.PopSequence();
        return X509CertificateLoader.LoadCertificate(output.Encode());
    }
}
