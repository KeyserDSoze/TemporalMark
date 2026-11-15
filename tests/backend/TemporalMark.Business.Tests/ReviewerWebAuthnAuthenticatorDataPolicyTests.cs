using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using TemporalMark.Business.Tenancy;
using Xunit;

namespace TemporalMark.Business.Tests;

/// <summary>
/// RED-first guards on completely UNTRUSTED authenticatorData. A passing
/// structural preflight is NEVER a signature, consent, or authorization.
/// </summary>
public sealed class ReviewerWebAuthnAuthenticatorDataPolicyTests
{
    private static readonly ReviewerWebAuthnRelyingPartyPolicy Rp =
        new("review.example.org", "https://review.example.org");

    private static byte[] SyntheticData(byte flags = 0x05, uint counter = 0)
    {
        var bytes = new byte[37];
        SHA256.HashData(Encoding.UTF8.GetBytes(Rp.RelyingPartyId)).CopyTo(bytes, 0);
        bytes[32] = flags;
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(33, 4), counter);
        return bytes;
    }

    [Theory]
    [InlineData(0x05, 0u, false, false)]
    [InlineData(0x05, 0x01020304u, false, false)]
    [InlineData(0x0D, 0u, true, false)]
    [InlineData(0x1D, 0xffffffffu, true, true)]
    public void ParsesOnlyValidUntrustedAssertionFlagsAndBigEndianCounter(
        int flags, uint counter, bool backupEligible, bool backedUp)
    {
        var bytes = SyntheticData((byte)flags, counter);

        Assert.True(ReviewerWebAuthnAuthenticatorDataPolicy.TryReadUntrustedAssertionData(
            bytes, Rp, out var data));
        Assert.NotNull(data);
        Assert.Equal(counter, data!.SignCount);
        Assert.Equal(backupEligible, data.BackupEligible);
        Assert.Equal(backedUp, data.BackedUp);
        Assert.Equal((byte)flags, bytes[32]); // Raw bytes remain unchanged.
    }

    [Theory]
    [InlineData(0x00)] // no presence and no verification
    [InlineData(0x01)] // user presence alone is NOT UV
    [InlineData(0x04)] // UV alone: this profile requires UP too
    [InlineData(0x07)] // RFU1 (bit 1)
    [InlineData(0x25)] // RFU2 (bit 5)
    [InlineData(0x45)] // attested credential data (AT), not an assertion
    [InlineData(0x85)] // extensions (ED), unsupported in strict profile
    [InlineData(0x15)] // BS without BE is forbidden
    [InlineData(0x1C)] // missing UP
    [InlineData(0xFF)] // reserved/unsupported bits and flags
    public void RejectsInvalidFlagsEvenWithCorrectRpIdHash(int flags)
    {
        Assert.False(ReviewerWebAuthnAuthenticatorDataPolicy.TryReadUntrustedAssertionData(
            SyntheticData((byte)flags), Rp, out var metadata));
        Assert.Null(metadata);
    }

    [Fact]
    public void All256FlagCombinationsDenyExceptRequiredUpUvAndValidBackupStates()
    {
        for (var flags = 0; flags <= byte.MaxValue; flags++)
        {
            var expected = flags is 0x05 or 0x0D or 0x1D;
            var accepted = ReviewerWebAuthnAuthenticatorDataPolicy
                .TryReadUntrustedAssertionData(SyntheticData((byte)flags), Rp, out _);
            Assert.Equal(expected, accepted);
        }
    }

    [Fact]
    public void RpIdHashUsesKnownSha256VectorNotAnOriginOrArbitraryString()
    {
        const string knownRpHash =
            "D4DD91016ABB2E47EBC359806AB5081FC410724A84F2D2D96D858FF55D35503A";
        var bytes = SyntheticData();
        Assert.Equal(knownRpHash, Convert.ToHexString(bytes.AsSpan(0, 32)));
        Assert.True(ReviewerWebAuthnAuthenticatorDataPolicy
            .TryReadUntrustedAssertionData(bytes, Rp, out _));
    }

    [Fact]
    public void DoesNotTrustCallerSelectedRpIdOrChangedHash()
    {
        var genuineShape = SyntheticData();
        var otherRp = new ReviewerWebAuthnRelyingPartyPolicy(
            "attacker.example.org", "https://attacker.example.org");
        Assert.False(ReviewerWebAuthnAuthenticatorDataPolicy.TryReadUntrustedAssertionData(
            genuineShape, otherRp, out _));

        var changed = genuineShape.ToArray();
        changed[0] ^= 1;
        Assert.False(ReviewerWebAuthnAuthenticatorDataPolicy.TryReadUntrustedAssertionData(
            changed, Rp, out _));
        Assert.False(ReviewerWebAuthnAuthenticatorDataPolicy.TryReadUntrustedAssertionData(
            new byte[37], Rp, out _));
    }

    [Fact]
    public void RejectsTruncationTrailingBytesAndMissingTrustedConfiguration()
    {
        var valid = SyntheticData();
        foreach (var malformed in new[]
        {
            Array.Empty<byte>(), new byte[1], valid[..31], valid[..36],
            valid.Concat(new byte[]{0}).ToArray(), new byte[8192]
        })
        {
            Assert.False(ReviewerWebAuthnAuthenticatorDataPolicy.TryReadUntrustedAssertionData(
                malformed, Rp, out var metadata));
            Assert.Null(metadata);
        }

        Assert.False(ReviewerWebAuthnAuthenticatorDataPolicy.TryReadUntrustedAssertionData(
            null, Rp, out _));
        Assert.False(ReviewerWebAuthnAuthenticatorDataPolicy.TryReadUntrustedAssertionData(
            valid, null, out _));
    }
}
