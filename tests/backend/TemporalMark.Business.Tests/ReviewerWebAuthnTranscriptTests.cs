using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using TemporalMark.Business.Tenancy;
using Xunit;

namespace TemporalMark.Business.Tests;

/// <summary>
/// RED-first byte-for-byte WebAuthn signing transcript. Passing means only
/// two UNTRUSTED structures had plausible syntax and the bytes were combined.
/// It never proves possession of a registered signer or a reviewed decision.
/// </summary>
public sealed class ReviewerWebAuthnTranscriptTests
{
    private static readonly ReviewerWebAuthnRelyingPartyPolicy Rp =
        new("review.example.org", "https://review.example.org");

    private static readonly byte[] Nonce =
        Enumerable.Range(0, 48).Select(i => (byte)i).ToArray();

    private const string ValidClientJson =
        """{"type":"webauthn.get","challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v","origin":"https://review.example.org","crossOrigin":false}""";

    private static byte[] AuthData()
    {
        var auth = new byte[37];
        SHA256.HashData(Encoding.ASCII.GetBytes(Rp.RelyingPartyId)).CopyTo(auth, 0);
        auth[32] = 0x05; // UP + UV: only self-reported until signature verified
        BinaryPrimitives.WriteUInt32BigEndian(auth.AsSpan(33, 4), 0x01020304);
        return auth;
    }

    private static byte[] ClientData() => Encoding.UTF8.GetBytes(ValidClientJson);

    [Fact]
    public void BuildsExact69ByteUnsignedTranscriptWithIndependentTestVector()
    {
        var auth = AuthData();
        var client = ClientData();
        Assert.True(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
            auth, client, Nonce, Rp, out var untrusted));
        Assert.NotNull(untrusted);
        Assert.Equal(69, untrusted!.Length);

        const string expectedHex =
            "D4DD91016ABB2E47EBC359806AB5081FC410724A84F2D2D96D858FF55D35503A" +
            "0501020304" +
            "2CFF8C24C5109350FB22FC58544E9634298ACF5B723332A174D3F745857C6CAB";
        Assert.Equal(expectedHex, Convert.ToHexString(untrusted));
        Assert.Equal("8396A0493110E2A5B7DD7711EE28C077186C6C67DF0886178D8B9DC0CAF54C83",
            Convert.ToHexString(SHA256.HashData(untrusted)));
        Assert.Equal(ValidClientJson, Encoding.UTF8.GetString(client));
        Assert.Equal((byte)0x05, auth[32]);
    }

    [Fact]
    public void PreservesOriginalJsonBytesRatherThanReserializingEquivalentClientData()
    {
        var original = ClientData();
        var reordered = Encoding.UTF8.GetBytes(
            """{"crossOrigin":false,"origin":"https://review.example.org","challenge":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v","type":"webauthn.get"}""");
        Assert.True(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
            AuthData(), original, Nonce, Rp, out var first));
        Assert.True(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
            AuthData(), reordered, Nonce, Rp, out var second));
        Assert.NotEqual(Convert.ToHexString(first!), Convert.ToHexString(second!));

        var withBom = new byte[] { 0xEF, 0xBB, 0xBF }
            .Concat(original).ToArray();
        Assert.True(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
            AuthData(), withBom, Nonce, Rp, out var bomTranscript));
        Assert.NotEqual(Convert.ToHexString(first!), Convert.ToHexString(bomTranscript!));
        Assert.Equal("C5B09C98C3D5F4577DFCF64D373D0288F3E22027443971BECDC26DAEF167A4DF",
            Convert.ToHexString(SHA256.HashData(bomTranscript!)));
    }

    [Fact]
    public void ReturnedTranscriptIsIndependentOfMutableUntrustedInputArrays()
    {
        var auth = AuthData();
        var client = ClientData();
        Assert.True(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
            auth, client, Nonce, Rp, out var snapshot));
        Assert.NotNull(snapshot);
        var frozen = Convert.ToHexString(snapshot!);
        auth[0] ^= 1;
        client[0] ^= 1;
        Assert.Equal(frozen, Convert.ToHexString(snapshot!));
    }

    [Fact]
    public void RejectsAnyUntrustedInputThatFailsEitherExistingPreflight()
    {
        var validAuth = AuthData();
        var validClient = ClientData();
        var forgedRp = validAuth.ToArray();
        forgedRp[0] ^= 1;
        var absentUv = validAuth.ToArray();
        absentUv[32] = 0x01;
        var unexpectedExtension = validAuth.ToArray();
        unexpectedExtension[32] |= 0x80;
        var unexpectedTrailing = validAuth.Concat(new byte[] { 0 }).ToArray();

        foreach (var invalidAuth in new[]
        {
            forgedRp, absentUv, unexpectedExtension, unexpectedTrailing,
            validAuth[..36], Array.Empty<byte>()
        })
        {
            Assert.False(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
                invalidAuth, validClient, Nonce, Rp, out var transcript));
            Assert.Null(transcript);
        }

        foreach (var invalidClient in new[]
        {
            Encoding.UTF8.GetBytes(ValidClientJson.Replace(
                "webauthn.get", "webauthn.create", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(ValidClientJson.Replace(
                "https://review.example.org", "https://attacker.example.org",
                StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(ValidClientJson.Replace(
                "crossOrigin\":false", "crossOrigin\":true", StringComparison.Ordinal)),
            Encoding.UTF8.GetBytes(ValidClientJson.Replace(
                "AAECAwQFBgcI", "BAECAwQFBgcI", StringComparison.Ordinal)),
            new byte[] { 0xFF }, new byte[4097]
        })
        {
            Assert.False(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
                validAuth, invalidClient, Nonce, Rp, out var transcript));
            Assert.Null(transcript);
        }
    }

    [Fact]
    public void FailsClosedWithMissingPolicyOrWrongTrustedServerNonce()
    {
        var badNonce = Nonce.ToArray();
        badNonce[4] ^= 1;
        Assert.False(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
            AuthData(), ClientData(), badNonce, Rp, out var bad));
        Assert.Null(bad);

        Assert.False(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
            AuthData(), ClientData(), new byte[47], Rp, out _));
        Assert.False(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
            AuthData(), ClientData(), Nonce, null, out _));
        Assert.False(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
            null, ClientData(), Nonce, Rp, out _));
        Assert.False(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
            AuthData(), null, Nonce, Rp, out _));
        Assert.False(ReviewerWebAuthnUnsignedAssertionTranscript.TryBuild(
            AuthData(), ClientData(), null, Rp, out _));
    }
}
