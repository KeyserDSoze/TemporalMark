using System.Formats.Asn1;
using System.Globalization;
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
    private const string FloorConfigurationError =
        "An operator-approved canonical positive CRLNumber minimum is required.";
    private const string ResponseError =
        "The RFC 3161 TSA signer does not have an acceptable issuer-signed CRL at issuance.";

    /// <summary>
    /// Parse a deployment-reviewed minimum signed CRLNumber. RFC5280
    /// requires a monotonically increasing number per issuer/scope with
    /// at most 20 unsigned octets; this floor is NOT a witnessed monotonic
    /// store and MUST be maintained independently by the operator.
    /// </summary>
    public static BigInteger ParseRequiredCrlNumberFloor(string? raw)
    {
        if (string.IsNullOrEmpty(raw) || raw.Length > 49 ||
            raw[0] == '0')
            throw new TimestampProviderUnavailableException(FloorConfigurationError);

        foreach (var c in raw)
        {
            if (c is < '0' or > '9')
                throw new TimestampProviderUnavailableException(FloorConfigurationError);
        }

        if (!BigInteger.TryParse(raw, NumberStyles.None,
                CultureInfo.InvariantCulture, out var minimum) ||
            minimum <= BigInteger.Zero ||
            minimum.ToByteArray(isUnsigned: true, isBigEndian: true).Length > 20)
            throw new TimestampProviderUnavailableException(FloorConfigurationError);

        return minimum;
    }

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

    /// <summary>
    /// Verify the actual cryptographically verified CMS signer against its
    /// already path-validated selected issuer(s). Each non-root certificate
    /// requires a separately signed full CRL from its immediate CA.
    /// Exactly one intermediate is supported; longer paths fail closed.
    /// </summary>
    public static void ValidateSignerPathRevocation(
        X509Certificate2? verifiedSigner,
        X509Certificate2 approvedRoot,
        X509Certificate2Collection cmsCertificates,
        ReadOnlyMemory<byte> rootCrlDer,
        ReadOnlyMemory<byte> intermediateIssuerCrlDer,
        DateTimeOffset signedGenTime,
        BigInteger rootCrlNumberFloor = default,
        BigInteger intermediateCrlNumberFloor = default)
    {
        if (rootCrlNumberFloor < BigInteger.Zero ||
            intermediateCrlNumberFloor < BigInteger.Zero)
            throw new TimestampProviderResponseException(ResponseError);

        using var chain = ExternalRfc3161CertificateChainPolicy.BuildValidatedSignerChain(
            verifiedSigner, approvedRoot, cmsCertificates, signedGenTime);
        var elements = chain.ChainElements;

        if (elements.Count is < 2 or > 3)
            throw new TimestampProviderResponseException(ResponseError);

        if (elements.Count == 2)
        {
            // The directly root-issued signer has exactly one issuer.
            // Reject a supplied but unused second CRL to avoid a silent
            // misconfiguration, stale approval or ambiguity about topology.
            if (!intermediateIssuerCrlDer.IsEmpty ||
                intermediateCrlNumberFloor != BigInteger.Zero)
                throw new TimestampProviderResponseException(ResponseError);
            ValidateDirectIssuerLeaf(
                elements[0].Certificate, elements[1].Certificate,
                rootCrlDer, signedGenTime, rootCrlNumberFloor);
            return;
        }

        // The selected chain is signer -> intermediate -> approved root.
        // The root CRL checks the intermediate CA certificate's status.
        // Only THEN the intermediate CA's own signed CRL can attest to
        // the verified TSA signer leaf's status; no partial NoCheck path.
        if (intermediateIssuerCrlDer.IsEmpty)
            throw new TimestampProviderResponseException(ResponseError);

        ValidateDirectIssuerLeaf(
            elements[1].Certificate, elements[2].Certificate,
            rootCrlDer, signedGenTime, rootCrlNumberFloor);
        ValidateDirectIssuerLeaf(
            elements[0].Certificate, elements[1].Certificate,
            intermediateIssuerCrlDer, signedGenTime, intermediateCrlNumberFloor);
    }

    public static void ValidateDirectIssuerLeaf(
        X509Certificate2? verifiedSigner,
        X509Certificate2 approvedRoot,
        ReadOnlyMemory<byte> approvedCrlDer,
        DateTimeOffset signedGenTime,
        BigInteger minimumCrlNumber = default)
    {
        if (minimumCrlNumber < BigInteger.Zero)
            throw new TimestampProviderResponseException(ResponseError);

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
                signedGenTime >= info.NextUpdate ||
                info.CrlNumber < minimumCrlNumber)
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
        BigInteger crlNumber = BigInteger.MinusOne;
        byte[]? aki = null;
        while (extensions.HasData)
        {
            var extension = extensions.ReadSequence();
            var oid = extension.ReadObjectIdentifier();
            bool critical = false;
            if (extension.HasData && IsUniversalTag(extension, UniversalTagNumber.Boolean))
                critical = extension.ReadBoolean();
            var encoded = extension.ReadOctetString();
            // RFC5280 requires CRLNumber (and AKI) to be non-critical.
            // Unknown extensions remain fail-closed below.
            if (extension.HasData || critical)
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
                crlNumber = numberReader.ReadInteger();
                if (crlNumber.Sign < 0 ||
                    crlNumber.ToByteArray(isUnsigned: true, isBigEndian: true).Length > 20 ||
                    numberReader.HasData)
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
            thisUpdate, nextUpdate, aki, crlNumber, revoked);
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
        byte[] AuthorityKeyIdentifier, BigInteger CrlNumber,
        HashSet<BigInteger> RevokedSerialNumbers);
}
