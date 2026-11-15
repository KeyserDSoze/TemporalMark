using System.Text;
using System.Text.Json;
using TemporalMark.Business.Tenancy;
using Xunit;

namespace TemporalMark.Business.Tests;

/// <summary>
/// RED first. These tests do NOT prove a signed WebAuthn assertion: even a
/// passing untrusted clientDataJSON must be cryptographically authenticated
/// by an audited verifier with a separately approved reviewer-held credential.
/// </summary>
public sealed class ReviewerWebAuthnClientDataPolicyTests
{
    private const string Origin = "https://review.example.org";
    private static readonly ReviewerWebAuthnRelyingPartyPolicy Rp =
        new("review.example.org", Origin);
    private static readonly byte[] ServerNonce =
        Enumerable.Range(0, 48).Select(i => (byte)i).ToArray();
    private static string Challenge =>
        Convert.ToBase64String(ServerNonce).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value);

    private static string Json(string type = "webauthn.get",
        string? challenge = null, string origin = Origin) =>
        JsonSerializer.Serialize(new { type, challenge = challenge ?? Challenge, origin,
            crossOrigin = false });

    [Fact]
    public void OnlyExactServerNonceAndPinnedOriginPassPreflight()
    {
        var bytes = Utf8(Json());
        Assert.True(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            bytes, ServerNonce, Rp));

        var alteredNonce = ServerNonce.ToArray();
        alteredNonce[11] ^= 1;
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            bytes, alteredNonce, Rp));
    }

    [Fact]
    public void AcceptsW3cUnknownFieldsAndReorderedKnownProperties()
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["vendorExtension"] = new { nested = true, a = 2 },
            ["origin"] = Origin,
            ["crossOrigin"] = false,
            ["challenge"] = Challenge,
            ["type"] = "webauthn.get"
        });
        Assert.True(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(json), ServerNonce, Rp));

        var withoutCrossOrigin = JsonSerializer.Serialize(new
            { challenge = Challenge, origin = Origin, type = "webauthn.get" });
        Assert.True(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(withoutCrossOrigin), ServerNonce, Rp));
    }

    [Theory]
    [InlineData("webauthn.create")]
    [InlineData("webauthn.get ")]
    [InlineData("WebAuthn.get")]
    [InlineData("")]
    public void RejectsAnyNonAssertionType(string type) =>
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(Json(type: type)), ServerNonce, Rp));

    [Theory]
    [InlineData("http://review.example.org")]
    [InlineData("https://review.example.org.attacker.test")]
    [InlineData("https://sub.review.example.org")]
    [InlineData("https://review.example.org:8443")]
    [InlineData("https://REVIEW.example.org")]
    [InlineData("https://attacker.test")]
    [InlineData("")]
    public void RejectsAnyOriginOtherThanServerPinnedOrigin(string origin) =>
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(Json(origin: origin)), ServerNonce, Rp));

    [Fact]
    public void RejectsNoncanonicalOrForgedChallenge()
    {
        foreach (var challenge in new[]
        {
            Challenge + "=", Challenge + "\n", Challenge.ToLowerInvariant(),
            Convert.ToBase64String(ServerNonce), 
            Convert.ToBase64String(ServerNonce).Replace('+','-').Replace('/','_') + " ",
            "AA", "", new string('A', 64)
        })
        {
            if (challenge == Challenge) continue;
            Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
                Utf8(Json(challenge: challenge)), ServerNonce, Rp));
        }
    }

    [Theory]
    [InlineData("true")]
    [InlineData("null")]
    [InlineData("\"false\"")]
    [InlineData("0")]
    [InlineData("[]")]
    public void RejectsCrossOriginIframeOrMalformedCrossOriginProperty(string value)
    {
        var json = Json().Replace("\"crossOrigin\":false", "\"crossOrigin\":" + value,
            StringComparison.Ordinal);
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(json), ServerNonce, Rp));
    }

    [Fact]
    public void RejectsTopOriginEvenWhenCrossOriginIsFalseOrMissing()
    {
        var withTop = Json().Replace("\"crossOrigin\":false",
            "\"crossOrigin\":false,\"topOrigin\":\"https://review.example.org\"",
            StringComparison.Ordinal);
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(withTop), ServerNonce, Rp));

        var withoutFlag = JsonSerializer.Serialize(new
            { type = "webauthn.get", challenge = Challenge, origin = Origin,
                topOrigin = Origin });
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(withoutFlag), ServerNonce, Rp));
    }

    [Fact]
    public void RejectsDuplicatedOrEscapedSecurityPropertyNames()
    {
        var json = Json();
        var duplicate = json.Replace("\"type\":\"webauthn.get\"",
            "\"type\":\"webauthn.get\",\"type\":\"webauthn.create\"",
            StringComparison.Ordinal);
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(duplicate), ServerNonce, Rp));

        // Escaped property alias decodes to the SAME "type" JSON member name.
        var alias = json.Replace("\"type\":\"webauthn.get\"",
            "\"type\":\"webauthn.get\",\"ty\\u0070e\":\"webauthn.create\"",
            StringComparison.Ordinal);
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(alias), ServerNonce, Rp));

        var duplicateChallenge = json.Replace("\"origin\":",
            "\"challenge\":\"wrong\",\"origin\":", StringComparison.Ordinal);
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(duplicateChallenge), ServerNonce, Rp));
    }

    [Fact]
    public void RejectsMissingMembersWrongTypesMalformedJsonAndInvalidUtf8()
    {
        foreach (var payload in new[]
        {
            "{}", "[]", "null", "true",
            "{\"type\":\"webauthn.get\",\"origin\":\"https://review.example.org\"}",
            "{\"type\":\"webauthn.get\",\"challenge\":\""+Challenge+"\"}",
            "{\"type\":2,\"challenge\":\""+Challenge+"\",\"origin\":\""+Origin+"\"}",
            "{\"type\":\"webauthn.get\",\"challenge\":null,\"origin\":\""+Origin+"\"}",
            "{\"type\":\"webauthn.get\",\"challenge\":\""+Challenge+"\",\"origin\":123}",
            "{not-json}", Json() + " trailing"
        })
            Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
                Utf8(payload), ServerNonce, Rp));

        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            new byte[] { 0x7B, 0x22, 0xC3, 0x28, 0x22, 0x7D }, ServerNonce, Rp));
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            new byte[4097], ServerNonce, Rp));
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            null, ServerNonce, Rp));
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(Json()), new byte[47], Rp));
        Assert.False(ReviewerWebAuthnClientDataPolicy.MatchesUntrustedClientData(
            Utf8(Json()), ServerNonce, null));
    }
}
