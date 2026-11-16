using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using TemporalMark.Business.Stamping;

namespace TemporalMark.Infrastructure.Timestamping;

/// <summary>
/// Intentionally narrow RFC5280 issuer-signed FULL CRL verifier, for a
/// directly root-issued TSA signing leaf. Never treat it as all-hop
/// historical OCSP/CRL or qualified EU Trusted List validation.
/// </summary>
public static class ExternalRfc3161IssuerCrlPolicy
{
    private const int MaximumCrlBytes = 1024 * 1024;
    private const string RsaSha256Oid = "1.2.840.113549.1.1.11";
    private const string CrlNumberOid = "2.5.29.20";
    private const string AuthorityKeyIdentifierOid = "2.5.29.35";
    private const string ConfigurationError =
        "A valid operator-reviewed complete DER issuer CRL in canonical Base64 is required.";
    private const string ResponseError =
        "The RFC 3161 TSA signer does not have an acceptable issuer-signed CRL at issuance.";

    public static byte[] ParseRequiredCrlBase64Der(string? base64)
    {
        if (string.IsNullOrEmpty(base64) ||
            base64.Length > ((MaximumCrlBytes + 2) / 3) * 4 ||
            base64.Length % 4 != 0)
            throw new TimestampProviderUnavailableException(ConfigurationError);

        foreach (var c in base64)
        {
            if (!((c is >= 'A' and <= 'Z') ||
                  (c is >= 'a' and <= 'z') ||
                  (c is >= '0' and <= '9') ||
                  c is '+' or '/' or '='))
                throw new TimestampProviderUnavailableException(ConfigurationError);
        }

        try
        {
            var der = Convert.FromBase64String(base64);
            if (der.Length == 0 || der.Length > MaximumCrlBytes ||
                !string.Equals(Convert.ToBase64String(der), base64, StringComparison.Ordinal))
                throw new TimestampProviderUnavailableException(ConfigurationError);

            // Decode all DER and reject unsupported delta/indirect/critical
            // semantics before any HTTP request. Signature/issuer identity
            // are checked later against the *verified* CMS signer and root.
            ReadFullCrl(der);
            return der;
        }
        catch (AsnContentException)
        {
            throw new TimestampProviderUnavailableException(ConfigurationError);
        }
        catch (CryptographicException)
        {
            throw new TimestampProviderUnavailableException(ConfigurationError);
        }
        catch (FormatException)
        {
            throw new TimestampProviderUnavailableException(ConfigurationError);
        }
        catch (ArgumentException)
        {
            throw new TimestampProviderUnavailableException(ConfigurationError);
        }
    }

    public static void ValidateDirectIssuerLeaf(
        X509Certificate2? verifiedSigner,
        X509Certificate2 approvedRoot,
        ReadOnlyMemory<byte> approvedCrlDer,
        DateTimeOffset signedGenTime)
    {
        if (verifiedSigner is null || approvedRoot is null ||
            approvedCrlDer.IsEmpty || approvedCrlDer.Length > MaximumCrlBytes)
            throw new TimestampProviderResponseException(ResponseError);

        try
        {
            // Single CRL covers only direct root -> TSA leaf. Reject ALL
            // chains with intermediates, never silently skip their revocation.
            if (!verifiedSigner.IssuerName.RawData.AsSpan()
                    .SequenceEqual(approvedRoot.SubjectName.RawData))
                throw new TimestampProviderResponseException(ResponseError);

            var keyUsage = approvedRoot.Extensions.OfType<X509KeyUsageExtension>().ToArray();
            if (keyUsage.Length != 1 ||
                !keyUsage[0].KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign))
                throw new TimestampProviderResponseException(ResponseError);

            var info = ReadFullCrl(approvedCrlDer);
            if (!info.IssuerDer.AsSpan().SequenceEqual(approvedRoot.SubjectName.RawData) ||
                signedGenTime < info.ThisUpdate ||
                signedGenTime >= info.NextUpdate)
                throw new TimestampProviderResponseException(ResponseError);

            var ski = approvedRoot.Extensions
                .OfType<X509SubjectKeyIdentifierExtension>().SingleOrDefault();
            if (ski?.SubjectKeyIdentifier is null ||
                !CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(ski.SubjectKeyIdentifier), info.AuthorityKeyIdentifier))
                throw new TimestampProviderResponseException(ResponseError);

            using var rsa = approvedRoot.GetRSAPublicKey();
            if (rsa is null ||
                !rsa.VerifyData(info.TbsDer, info.Signature,
                    HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                throw new TimestampProviderResponseException(ResponseError);

            var serial = new BigInteger(
                Convert.FromHexString(verifiedSigner.SerialNumber),
                isUnsigned: true, isBigEndian: true);
            if (info.RevokedSerialNumbers.Contains(serial))
                throw new TimestampProviderResponseException(ResponseError);
        }
        catch (AsnContentException)
        {
            throw new TimestampProviderResponseException(ResponseError);
        }
        catch (CryptographicException)
        {
            throw new TimestampProviderResponseException(ResponseError);
        }
        catch (FormatException)
        {
            throw new TimestampProviderResponseException(ResponseError);
        }
        catch (ArgumentException)
        {
            throw new TimestampProviderResponseException(ResponseError);
        }
        catch (InvalidOperationException)
        {
            throw new TimestampProviderResponseException(ResponseError);
        }
    }

    private static ParsedFullCrl ReadFullCrl(ReadOnlyMemory<byte> der)
    {
        var outerReader = new AsnReader(der, AsnEncodingRules.DER);
        var outer = outerReader.ReadSequence();
        var tbsDer = outer.ReadEncodedValue();
        var outerAlgorithm = outer.ReadEncodedValue();
        var signature = outer.ReadBitString(out var unusedBitCount);
        if (unusedBitCount != 0 || outer.HasData || outerReader.HasData)
            throw new AsnContentException();

        var tbsReader = new AsnReader(tbsDer, AsnEncodingRules.DER);
        var tbs = tbsReader.ReadSequence();
        // Only X.509 v2 COMPLETE CRLs are accepted.
        if (!IsUniversalTag(tbs, UniversalTagNumber.Integer) ||
            tbs.ReadInteger() != BigInteger.One)
            throw new AsnContentException();

        var innerAlgorithm = tbs.ReadEncodedValue();
        if (!innerAlgorithm.Span.SequenceEqual(outerAlgorithm.Span))
            throw new AsnContentException();

        var algorithmReader = new AsnReader(innerAlgorithm, AsnEncodingRules.DER);
        var algorithm = algorithmReader.ReadSequence();
        if (algorithm.ReadObjectIdentifier() != RsaSha256Oid)
            throw new AsnContentException();
        // DER sha256WithRSAEncryption AlgorithmIdentifier uses NULL.
        algorithm.ReadNull();
        if (algorithm.HasData || algorithmReader.HasData)
            throw new AsnContentException();

        var issuerDer = tbs.ReadEncodedValue().ToArray();
        var thisUpdate = ReadTime(tbs);
        if (!IsUniversalTag(tbs, UniversalTagNumber.UtcTime) &&
            !IsUniversalTag(tbs, UniversalTagNumber.GeneralizedTime))
            throw new AsnContentException();
        var nextUpdate = ReadTime(tbs);
        if (nextUpdate <= thisUpdate)
            throw new AsnContentException();

        var revoked = new HashSet<BigInteger>();
        if (tbs.HasData && IsUniversalTag(tbs, UniversalTagNumber.Sequence))
        {
            var entries = tbs.ReadSequence();
            while (entries.HasData)
            {
                var item = entries.ReadSequence();
                var serial = item.ReadInteger();
                if (serial.Sign <= 0 || !revoked.Add(serial))
                    throw new AsnContentException();
                ReadTime(item);
                // The first slice does not implement reasonCode,
                // invalidityDate, certificateIssuer or removeFromCRL:
                // fail closed rather than mistake them for clean status.
                if (item.HasData)
                    throw new AsnContentException();
            }
        }

        if (!tbs.HasData)
            throw new AsnContentException(); // RFC5280 v2 CRL needs AKI/CRLNumber.

        var explicitTag = new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true);
        var extensionWrapper = tbs.ReadSequence(explicitTag);
        var extensions = extensionWrapper.ReadSequence();
        bool hasAki = false, hasNumber = false;
        byte[]? aki = null;
        while (extensions.HasData)
        {
            var extension = extensions.ReadSequence();
            var oid = extension.ReadObjectIdentifier();
            if (extension.HasData && IsUniversalTag(extension, UniversalTagNumber.Boolean))
                extension.ReadBoolean();
            var encoded = extension.ReadOctetString();
            if (extension.HasData)
                throw new AsnContentException();

            if (oid == AuthorityKeyIdentifierOid && !hasAki)
            {
                hasAki = true;
                var akiReader = new AsnReader(encoded, AsnEncodingRules.DER);
                var akiSequence = akiReader.ReadSequence();
                aki = akiSequence.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
                // Scope limited to keyIdentifier only (no indirect issuer/serial).
                if (aki.Length == 0 || akiSequence.HasData || akiReader.HasData)
                    throw new AsnContentException();
            }
            else if (oid == CrlNumberOid && !hasNumber)
            {
                hasNumber = true;
                var numberReader = new AsnReader(encoded, AsnEncodingRules.DER);
                if (numberReader.ReadInteger().Sign < 0 || numberReader.HasData)
                    throw new AsnContentException();
            }
            else
            {
                // Includes deltaCRLIndicator, issuingDistributionPoint,
                // unsupported critical extensions and duplicate OIDs.
                throw new AsnContentException();
            }
        }

        if (extensionWrapper.HasData || tbs.HasData || tbsReader.HasData ||
            !hasAki || !hasNumber || aki is null)
            throw new AsnContentException();

        return new ParsedFullCrl(
            tbsDer.ToArray(), signature, issuerDer,
            thisUpdate, nextUpdate, aki, revoked);
    }

    private static DateTimeOffset ReadTime(AsnReader reader)
    {
        if (IsUniversalTag(reader, UniversalTagNumber.UtcTime))
            return reader.ReadUtcTime();
        if (IsUniversalTag(reader, UniversalTagNumber.GeneralizedTime))
            return reader.ReadGeneralizedTime();
        throw new AsnContentException();
    }

    private static bool IsUniversalTag(AsnReader reader, UniversalTagNumber tag) =>
        reader.HasData && reader.PeekTag().TagClass == TagClass.Universal &&
        reader.PeekTag().TagValue == (int)tag;

    private sealed record ParsedFullCrl(
        byte[] TbsDer, byte[] Signature, byte[] IssuerDer,
        DateTimeOffset ThisUpdate, DateTimeOffset NextUpdate,
        byte[] AuthorityKeyIdentifier, HashSet<BigInteger> RevokedSerialNumbers);
}
