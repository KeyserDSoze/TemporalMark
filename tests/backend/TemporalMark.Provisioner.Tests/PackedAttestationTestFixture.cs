using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Fido2NetLib;
using Fido2NetLib.Objects;
using TemporalMark.Infrastructure.WebAuthn;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// Disposable TEST-ONLY browser/authenticator transcript. Builds CBOR but
/// does not parse, verify or authorize it; actual verification is performed
/// exclusively by production Fido2 4.3.3. Random ephemeral private keys and
/// its deliberately untrusted test CA must never be persisted or deployed.
/// </summary>
internal sealed class PackedAttestationTestFixture : IDisposable
{
    private const string RelyingPartyId = "review.example.org";
    private const string Origin = "https://review.example.org";
    private const string Issuer = "https://identity.example.org/realms/review";
    private static readonly Guid Aaguid =
        Guid.Parse("db4a769a-4441-47be-8a52-8a5c84db6788");

    private readonly ECDsa credentialKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa testRootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa attestationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    public CredentialCreateOptions Options { get; }
    public ReviewerRegistrationAttestationCeremony Ceremony { get; }
    public AuthenticatorAttestationRawResponse Response { get; }
    public byte[] CredentialId { get; }

    // ONLY for isolated cryptographic fixture tests. No persistent/global
    // unique-index guarantee, and no trust in the generated test certificate.
    public IsCredentialIdUniqueToUserAsyncDelegate TestOnlyUniqueCredentialId =>
        (_, _) => Task.FromResult(true);

    public static PackedAttestationTestFixture Create(string mutation = "") => new(mutation);

    private PackedAttestationTestFixture(string mutation)
    {
        CredentialId = RandomNumberGenerator.GetBytes(32);
        var challenge = RandomNumberGenerator.GetBytes(48);
        var userHandle = RandomNumberGenerator.GetBytes(32);

        Options = new CredentialCreateOptions
        {
            Rp = new PublicKeyCredentialRpEntity(RelyingPartyId, "TemporalMark Review"),
            User = new Fido2User
            {
                Name = "fixture-reviewer",
                DisplayName = "Test reviewer — no real credential",
                Id = userHandle
            },
            Challenge = challenge,
            PubKeyCredParams = PubKeyCredParam.Defaults,
            Attestation = AttestationConveyancePreference.Direct,
            AuthenticatorSelection = new AuthenticatorSelection
            {
                UserVerification = UserVerificationRequirement.Required
            }
        };
        Ceremony = new ReviewerRegistrationAttestationCeremony(
            Issuer, "fixture-reviewer-sub", "fixture-separate-registrar-sub",
            challenge.ToArray(), userHandle.ToArray(),
            DateTimeOffset.UtcNow.AddSeconds(-10),
            DateTimeOffset.UtcNow.AddSeconds(60));

        // Only the browser clientDataJSON is changed for these cases;
        // signatures are recomputed, proving origin/challenge rejection even
        // when the submitted transcript is cryptographically self-consistent.
        string origin = mutation == "wrong-origin" ? "https://attacker.example.org" : Origin;
        byte[] browserChallenge = mutation == "wrong-challenge"
            ? RandomNumberGenerator.GetBytes(48) : challenge;
        byte[] clientData = Encoding.UTF8.GetBytes(
            $"{{\"type\":\"webauthn.create\",\"challenge\":\"{Base64Url(browserChallenge)}\",\"origin\":\"{origin}\",\"crossOrigin\":false}}");

        byte[] rpHash = SHA256.HashData(Encoding.UTF8.GetBytes(
            mutation == "wrong-rp-hash" ? "attacker.example.org" : RelyingPartyId));

        // UP(0x01) + UV(0x04) + AT(0x40); no flags are forged as proof:
        // the real library must inspect them after authenticating the blob.
        byte flags = 0x45;
        if (mutation == "no-user-presence") flags &= unchecked((byte)~0x01);
        if (mutation == "no-user-verification") flags &= unchecked((byte)~0x04);

        byte[] credentialCose = CreateCredentialCosePublicKey(credentialKey);
        byte[] authenticatorData =
        [
            .. rpHash,
            flags,
            0, 0, 0, 0, // signCount = 0 (permitted by WebAuthn)
            .. Aaguid.ToByteArray(bigEndian: true),
            0, (byte)CredentialId.Length, // credential ID length, big-endian
            .. CredentialId,
            .. credentialCose
        ];

        byte[] signedMessage =
        [
            .. authenticatorData,
            .. SHA256.HashData(clientData)
        ];

        var now = DateTimeOffset.UtcNow;
        var rootRequest = new CertificateRequest(
            "CN=TemporalMark Test Attestation Root, O=TemporalMark Tests, C=IT",
            testRootKey, HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(true, false, 0, true));
        rootRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));

        using var root = rootRequest.CreateSelfSigned(now.AddMinutes(-5), now.AddDays(1));
        var leafRequest = new CertificateRequest(
            "CN=TemporalMark Test Attestor, OU=Authenticator Attestation, O=TemporalMark Tests, C=IT",
            attestationKey, HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        leafRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        using var leaf = leafRequest.Create(root, now.AddMinutes(-5), now.AddHours(12),
            RandomNumberGenerator.GetBytes(12));

        byte[] signature = attestationKey.SignData(
            signedMessage, HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);

        // Mutate AFTER signing: the maintained verifier, not this fixture,
        // must reject these actual signed-data/signature discrepancies.
        if (mutation == "tampered-authenticator-data")
            authenticatorData[35] ^= 0x01;
        if (mutation == "tampered-credential-public-key")
            authenticatorData[^1] ^= 0x01;
        if (mutation == "tampered-attestation-signature")
            signature[^1] ^= 0x01;

        byte[] certificate = mutation == "malformed-attestation-certificate"
            ? [0x30, 0x01, 0x00] : leaf.RawData;
        byte[] attestationObject = PackedAttestationObject(
            authenticatorData, signature, certificate, root.RawData);
        Response = new AuthenticatorAttestationRawResponse
        {
            Id = Base64Url(CredentialId),
            RawId = CredentialId.ToArray(),
            Type = PublicKeyCredentialType.PublicKey,
            ClientExtensionResults = new AuthenticationExtensionsClientOutputs(),
            Response = new AuthenticatorAttestationRawResponse.AttestationResponse
            {
                ClientDataJson = clientData,
                AttestationObject = attestationObject
            }
        };
    }

    private static byte[] CreateCredentialCosePublicKey(ECDsa key)
    {
        var parameters = key.ExportParameters(false);
        var writer = new CborWriter();
        writer.WriteStartMap(5);
        writer.WriteInt32(1); writer.WriteInt32(2); // kty = EC2
        writer.WriteInt32(3); writer.WriteInt32(-7); // alg = ES256
        writer.WriteInt32(-1); writer.WriteInt32(1); // crv = P-256
        writer.WriteInt32(-2); writer.WriteByteString(parameters.Q.X!);
        writer.WriteInt32(-3); writer.WriteByteString(parameters.Q.Y!);
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static byte[] PackedAttestationObject(
        byte[] authenticatorData, byte[] signature, byte[] leaf, byte[] root)
    {
        var writer = new CborWriter();
        writer.WriteStartMap(3);
        writer.WriteTextString("fmt"); writer.WriteTextString("packed");
        writer.WriteTextString("authData"); writer.WriteByteString(authenticatorData);
        writer.WriteTextString("attStmt");
        writer.WriteStartMap(3);
        writer.WriteTextString("alg"); writer.WriteInt32(-7);
        writer.WriteTextString("sig"); writer.WriteByteString(signature);
        writer.WriteTextString("x5c");
        writer.WriteStartArray(2);
        writer.WriteByteString(leaf);
        writer.WriteByteString(root);
        writer.WriteEndArray();
        writer.WriteEndMap();
        writer.WriteEndMap();
        return writer.Encode();
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public void Dispose()
    {
        attestationKey.Dispose();
        testRootKey.Dispose();
        credentialKey.Dispose();
    }
}
