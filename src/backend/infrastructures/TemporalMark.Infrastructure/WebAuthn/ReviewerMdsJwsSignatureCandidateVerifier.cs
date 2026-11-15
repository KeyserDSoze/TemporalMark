using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace TemporalMark.Infrastructure.WebAuthn;

/// <summary>
/// NON-AUTHORIZING result of JWS signature + explicitly supplied X509 path
/// checking. CRL/OCSP, official FIDO MDS root governance and immutable serial
/// persistence are deliberately NOT verified. Never use to enroll credentials.
/// </summary>
public sealed record ReviewerMdsJwsCryptographicCandidate(
    string ReviewStatus, string PolicyStage, int MetadataSerial,
    string SignedBlobSha256);

/// <summary>
/// An isolated cryptographic preflight for an ephemeral test trust root, NOT a
/// production FIDO MDS validator. An arbitrary caller may provide a fake root.
/// The X509Chain policy MUST NOT be mistaken for certificate revocation:
/// RevocationMode.NoCheck here makes every result UNAPPROVED, permanently.
/// No API, CLI, SQL, attestation or metadata model consumer invokes this.
/// See ADR 0029 and release blocker #57.
/// </summary>
public static class ReviewerMdsJwsSignatureCandidateVerifier
{
    private const int MaximumJwtCharacters = 1_000_000;
    private const int MaximumEncodedX5c = 12_000;
    private const int MaximumCertificates = 3;

    public static async Task<ReviewerMdsJwsCryptographicCandidate> InspectAsync(
        string? untrustedJwt, X509Certificate2? testSelectedRoot,
        DateTimeOffset nowUtc, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (string.IsNullOrWhiteSpace(untrustedJwt) ||
            untrustedJwt.Length > MaximumJwtCharacters ||
            testSelectedRoot is null ||
            nowUtc.Offset != TimeSpan.Zero)
            throw Denied();

        var parts = untrustedJwt.Split('.');
        if (parts.Length != 3 || parts.Any(s => string.IsNullOrEmpty(s)))
            throw Denied();

        using var certificates = new CertificateScope();
        try
        {
            using var header = ParseJson(DecodeBase64Url(parts[0]));
            var h = header.RootElement;
            if (h.ValueKind != JsonValueKind.Object ||
                h.EnumerateObject().Count() is < 4 or > 4)
                throw Denied();

            string? algorithm = null, type = null;
            long? issuedAt = null;
            foreach (var field in h.EnumerateObject())
            {
                switch (field.Name)
                {
                    case "alg":
                        if (algorithm is not null || field.Value.ValueKind != JsonValueKind.String)
                            throw Denied();
                        algorithm = field.Value.GetString();
                        break;
                    case "typ":
                        if (type is not null || field.Value.ValueKind != JsonValueKind.String)
                            throw Denied();
                        type = field.Value.GetString();
                        break;
                    case "iat":
                        if (issuedAt is not null || field.Value.ValueKind != JsonValueKind.Number ||
                            !field.Value.TryGetInt64(out var value))
                            throw Denied();
                        issuedAt = value;
                        break;
                    case "x5c":
                        if (certificates.Count != 0 ||
                            field.Value.ValueKind != JsonValueKind.Array ||
                            field.Value.GetArrayLength() is < 1 or > MaximumCertificates)
                            throw Denied();
                        foreach (var item in field.Value.EnumerateArray())
                        {
                            if (item.ValueKind != JsonValueKind.String)
                                throw Denied();
                            var text = item.GetString();
                            if (string.IsNullOrWhiteSpace(text) || text.Length > MaximumEncodedX5c)
                                throw Denied();
                            var rawCert = Convert.FromBase64String(text);
                            if (rawCert.Length is < 128 or > 8192)
                                throw Denied();
                            certificates.Add(X509CertificateLoader.LoadCertificate(rawCert));
                        }
                        break;
                    default:
                        // No x5u/jku/jwk/crit/kid or any caller-selected URL.
                        throw Denied();
                }
            }

            if (algorithm != SecurityAlgorithms.RsaSha256 ||
                type != "JWT" || !issuedAt.HasValue || certificates.Count == 0)
                throw Denied();

            DateTimeOffset signedTime;
            try { signedTime = DateTimeOffset.FromUnixTimeSeconds(issuedAt.Value); }
            catch (ArgumentOutOfRangeException) { throw Denied(); }
            if (signedTime > nowUtc || signedTime <= nowUtc.AddHours(-24))
                throw Denied();

            ValidateTestRootAndChain(certificates, testSelectedRoot, nowUtc);

            // Maintained Microsoft.IdentityModel verifies JWS bytes using ONLY
            // x5c[0] signing key after explicit test-root chain pinning. No
            // issuer/audience/expiry claims are expected for MDS, so apply
            // our own mandatory signed-header iat and serial checks.
            var handler = new JsonWebTokenHandler();
            var verified = await handler.ValidateTokenAsync(
                untrustedJwt,
                new TokenValidationParameters
                {
                    RequireSignedTokens = true,
                    RequireExpirationTime = false,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new X509SecurityKey(certificates[0]),
                    ValidAlgorithms = [SecurityAlgorithms.RsaSha256]
                });
            if (!verified.IsValid)
                throw Denied();

            // Minimal payload inspection AFTER signature verification; no
            // metadata entries or trusted signer objects escape.
            using var payload = ParseJson(DecodeBase64Url(parts[1]));
            var root = payload.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("no", out var serial) ||
                serial.ValueKind != JsonValueKind.Number ||
                !serial.TryGetInt32(out var no) || no <= 0 ||
                !root.TryGetProperty("legalHeader", out var legalHeader) ||
                legalHeader.ValueKind != JsonValueKind.String ||
                string.IsNullOrWhiteSpace(legalHeader.GetString()) ||
                !root.TryGetProperty("entries", out var entries) ||
                entries.ValueKind != JsonValueKind.Array)
                throw Denied();

            // Duplicate JSON fields are not defined for security-sensitive
            // claims and can lead to differential parser behavior.
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in root.EnumerateObject())
                if (!seen.Add(property.Name))
                    throw Denied();

            return new ReviewerMdsJwsCryptographicCandidate(
                "UNAPPROVED", "JWS_CHAIN_ONLY_REVOCATION_UNVERIFIED",
                no, Convert.ToHexString(
                    SHA256.HashData(Encoding.UTF8.GetBytes(untrustedJwt))));
        }
        catch (Exception e) when (e is FormatException or JsonException or
                                  CryptographicException or ArgumentException or
                                  SecurityTokenException or InvalidOperationException)
        {
            throw Denied();
        }
    }

    private static JsonDocument ParseJson(byte[] bytes) =>
        JsonDocument.Parse(bytes, new JsonDocumentOptions
        {
            AllowTrailingCommas = false, CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 16
        });

    private static byte[] DecodeBase64Url(string text)
    {
        if (text.Length == 0 || text.Length % 4 == 1 ||
            text.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            throw Denied();

        var decoded = Convert.FromBase64String(
            text.Replace('-', '+').Replace('_', '/') +
            new string('=', (4 - text.Length % 4) % 4));
        var roundTrip = Convert.ToBase64String(decoded).TrimEnd('=')
            .Replace('+', '-').Replace('/', '_');
        if (!string.Equals(roundTrip, text, StringComparison.Ordinal))
            throw Denied();
        return decoded;
    }

    private static void ValidateTestRootAndChain(
        CertificateScope path, X509Certificate2 root, DateTimeOffset now)
    {
        if (path.Count == 0 || path[0].Version != 3 ||
            root.Version != 3 ||
            !HasBasicConstraints(root, expectedCa: true) ||
            !HasKeyUsage(root, X509KeyUsageFlags.KeyCertSign) ||
            !HasBasicConstraints(path[0], expectedCa: false) ||
            !HasKeyUsage(path[0], X509KeyUsageFlags.DigitalSignature))
            throw Denied();

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        // This is intentionally NOT production revocation verification.
        // #57 must implement independently audited fail-closed CRL paths.
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = now.UtcDateTime;
        for (var i = 1; i < path.Count; i++)
            chain.ChainPolicy.ExtraStore.Add(path[i]);

        if (!chain.Build(path[0]) || chain.ChainElements.Count != path.Count + 1)
            throw Denied();
        for (var i = 0; i < path.Count; i++)
            if (!CryptographicOperations.FixedTimeEquals(
                    chain.ChainElements[i].Certificate.RawData, path[i].RawData))
                throw Denied();
        if (!CryptographicOperations.FixedTimeEquals(
                chain.ChainElements[^1].Certificate.RawData, root.RawData))
            throw Denied();
    }

    private static bool HasBasicConstraints(X509Certificate2 cert, bool expectedCa)
    {
        var constraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        return constraints.Length == 1 && constraints[0].CertificateAuthority == expectedCa;
    }

    private static bool HasKeyUsage(X509Certificate2 cert, X509KeyUsageFlags flag)
    {
        var extensions = cert.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        return extensions.Length == 1 && (extensions[0].KeyUsages & flag) == flag;
    }

    private static UnauthorizedAccessException Denied() =>
        new("FIDO MDS JWS and test-only X509 path cryptographic preflight denied.");

    private sealed class CertificateScope : IDisposable
    {
        private readonly List<X509Certificate2> certificates = [];
        public int Count => certificates.Count;
        public X509Certificate2 this[int index] => certificates[index];
        public void Add(X509Certificate2 cert) => certificates.Add(cert);
        public void Dispose()
        {
            foreach (var cert in certificates)
                cert.Dispose();
        }
    }
}
