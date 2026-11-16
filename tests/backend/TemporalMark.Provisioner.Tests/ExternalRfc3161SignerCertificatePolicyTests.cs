using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;
using TemporalMark.Infrastructure.Timestamping;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first: RFC 3161 §2.3 mandates one CRITICAL EKU extension containing
/// only id-kp-timeStamping. Ephemeral self-signed certificates are fixtures
/// for extension parsing, NOT QTSP issuers or trusted timestamp receipts.
/// </summary>
public sealed class ExternalRfc3161SignerCertificatePolicyTests
{
    private const string TimeStampingOid = "1.3.6.1.5.5.7.3.8";
    private const string ServerAuthenticationOid = "1.3.6.1.5.5.7.3.1";
    private const string CodeSigningOid = "1.3.6.1.5.5.7.3.3";
    private const string AnyExtendedKeyUsageOid = "2.5.29.37.0";

    [Fact]
    public void ExactlyOneCriticalTimeStampingEkuIsAccepted()
    {
        using var certificate = CreateCertificate(Eku(true, TimeStampingOid));

        ExternalRfc3161SignerCertificatePolicy.Validate(certificate);
    }

    [Fact]
    public void AbsentSignerCertificateMustFailClosed()
    {
        Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161SignerCertificatePolicy.Validate(null));
    }

    [Fact]
    public void MissingEkuExtensionMustFailClosed()
    {
        using var certificate = CreateCertificate();

        AssertRejected(certificate);
    }

    [Fact]
    public void NoncriticalTimeStampingEkuMustFailClosed()
    {
        using var certificate = CreateCertificate(Eku(false, TimeStampingOid));

        AssertRejected(certificate);
    }

    [Theory]
    [InlineData(ServerAuthenticationOid)]
    [InlineData(CodeSigningOid)]
    [InlineData(AnyExtendedKeyUsageOid)]
    public void OtherCriticalKeyPurposesAreNotTimestamping(string purposeOid)
    {
        using var certificate = CreateCertificate(Eku(true, purposeOid));

        AssertRejected(certificate);
    }

    [Theory]
    [InlineData(ServerAuthenticationOid)]
    [InlineData(CodeSigningOid)]
    [InlineData(AnyExtendedKeyUsageOid)]
    public void ExtraKeyPurposeBesideTimeStampingMustFailClosed(string otherOid)
    {
        using var certificate = CreateCertificate(Eku(true, TimeStampingOid, otherOid));

        AssertRejected(certificate);
    }

    [Fact]
    public void DuplicateTimeStampingOidWithinSingleEkuMustFailClosed()
    {
        using var certificate = CreateCertificate(Eku(true, TimeStampingOid, TimeStampingOid));

        AssertRejected(certificate);
    }

    [Fact]
    public void EmptyCriticalEkuMustFailClosed()
    {
        using var certificate = CreateCertificate(Eku(true));

        AssertRejected(certificate);
    }

    [Fact]
    public void MalformedCriticalEkuDerMustFailClosed()
    {
        // ASN.1 NULL is not the RFC 5280 SEQUENCE OF KeyPurposeId.
        using var certificate = CreateCertificate(
            new X509Extension(new Oid("2.5.29.37"), new byte[] { 0x05, 0x00 }, critical: true));

        AssertRejected(certificate);
    }

    [Fact]
    public void MultipleEkuExtensionsAreRejectedEvenIfOneIsValid()
    {
        using var certificate = CreateCertificate(
            Eku(true, TimeStampingOid),
            Eku(true, ServerAuthenticationOid));

        AssertRejected(certificate);
    }

    private static void AssertRejected(X509Certificate2 certificate)
    {
        var exception = Assert.Throws<TimestampProviderResponseException>(() =>
            ExternalRfc3161SignerCertificatePolicy.Validate(certificate));

        Assert.Contains("EKU", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static X509EnhancedKeyUsageExtension Eku(bool critical, params string[] purposes)
    {
        var oids = new OidCollection();
        foreach (var purpose in purposes)
            oids.Add(new Oid(purpose));

        return new X509EnhancedKeyUsageExtension(oids, critical);
    }

    private static X509Certificate2 CreateCertificate(params X509Extension[] extensions)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=Disposable RFC3161 EKU fixture",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        foreach (var extension in extensions)
            request.CertificateExtensions.Add(extension);

        return request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
    }
}
