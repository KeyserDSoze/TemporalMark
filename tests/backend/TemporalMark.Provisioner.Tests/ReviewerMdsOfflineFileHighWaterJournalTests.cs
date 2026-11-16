using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// RED-first disposable RSA-PSS cryptographic journal regression.
/// Local test files are NOT immutable, separately governed or production FIDO trust.
/// </summary>
public sealed class ReviewerMdsOfflineFileHighWaterJournalTests
{
    private sealed class Fixture : IDisposable
    {
        public string DirectoryPath { get; } =
            Path.Combine(Path.GetTempPath(), "temporalmark-signed-journal-" + Guid.NewGuid().ToString("N"));
        public string PathName => Path.Combine(DirectoryPath, "separate-witness.log");
        public string Policy { get; } = Hash("test-policy-" + Guid.NewGuid().ToString("N"));
        public RSA Key { get; } = RSA.Create(2048);
        public DateTimeOffset Now { get; } = DateTimeOffset.UtcNow;
        public string Pin => Convert.ToHexString(SHA256.HashData(Key.ExportSubjectPublicKeyInfo()));

        public Fixture()
        {
            System.IO.Directory.CreateDirectory(DirectoryPath);
        }

        public void Bootstrap() =>
            ReviewerMdsOfflineFileHighWaterJournal.BootstrapNewForTests(PathName, Policy, Pin);

        public byte[] Payload(long version, string sealSha, string previous,
            DateTimeOffset? issued = null) =>
            Encoding.ASCII.GetBytes(string.Join("\n",
            [
                "TEMPORALMARK-UNAPPROVED-SIGNED-FILE-HIGHWATER-EVENT-1",
                Policy,
                version.ToString(CultureInfo.InvariantCulture),
                sealSha,
                previous,
                (issued ?? Now.AddSeconds(-1)).ToUnixTimeSeconds()
                    .ToString(CultureInfo.InvariantCulture),
                ""
            ]));

        public ReviewerMdsFileHighWaterObservation Append(
            byte[] payload, byte[]? signature = null, RSA? key = null,
            string? policy = null, string? pin = null, DateTimeOffset? now = null) =>
            ReviewerMdsOfflineFileHighWaterJournal.AppendSignedForTests(
                PathName, policy ?? Policy, pin ?? Pin, key ?? Key,
                payload, signature ?? Key.SignData(payload, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss), now ?? Now);

        public ReviewerMdsFileHighWaterObservation Read(
            string? policy = null, string? pin = null, RSA? key = null,
            DateTimeOffset? now = null) =>
            ReviewerMdsOfflineFileHighWaterJournal.InspectLatest(
                PathName, policy ?? Policy, pin ?? Pin, key ?? Key, now ?? Now);

        public void Dispose()
        {
            Key.Dispose();
            System.IO.Directory.Delete(DirectoryPath, recursive: true);
        }
    }

    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    [Fact]
    public void NewJournalPersistsOnlyUnapprovedIncreasingSignedVersionsAcrossOpens()
    {
        using var f = new Fixture();
        Assert.Throws<UnauthorizedAccessException>(() => f.Read());
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(f.Payload(1, Hash("first"), new string('0', 64))));

        f.Bootstrap();
        Assert.Throws<UnauthorizedAccessException>(() => f.Read());
        Assert.Throws<UnauthorizedAccessException>(() => f.Bootstrap());

        var first = f.Append(f.Payload(3, Hash("first"), new string('0', 64)));
        Assert.Equal("UNAPPROVED", first.ReviewStatus);
        Assert.Equal("TEST_FILE_HIGH_WATER_NO_INDEPENDENT_CUSTODY", first.PolicyStage);
        Assert.Equal(3L, first.CandidateSerial);
        Assert.Equal(Hash("first"), first.SealSha256);
        Assert.Equal(3L, f.Read().CandidateSerial);

        var next = f.Append(f.Payload(4, Hash("second"), first.PayloadSha256));
        Assert.Equal(4L, next.CandidateSerial);
        Assert.Equal(Hash("second"), f.Read().SealSha256);
        Assert.Equal(next.PayloadSha256, f.Read().PayloadSha256);
        Assert.DoesNotContain(typeof(ReviewerMdsFileHighWaterObservation).GetProperties(),
            p => p.Name.Contains("Trusted", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("Approved", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("Active", StringComparison.OrdinalIgnoreCase) ||
                 p.Name.Contains("PublicKey", StringComparison.OrdinalIgnoreCase));

        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(f.Payload(3, Hash("first"), new string('0', 64))));
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(f.Payload(4, Hash("divergent"), next.PayloadSha256)));
        Assert.Equal(4L, f.Read().CandidateSerial);
    }

    [Fact]
    public void BadSignerPinSignaturePolicyOrHashChainAreAlwaysDenied()
    {
        using var f = new Fixture();
        f.Bootstrap();
        var first = f.Append(f.Payload(1, Hash("initial"), new string('0', 64)));
        using var otherKey = RSA.Create(2048);
        Assert.Throws<UnauthorizedAccessException>(() => f.Read(key: otherKey));
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Read(pin: Hash("attacker-signer")));
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Read(policy: Hash("other-policy")));

        var next = f.Payload(2, Hash("new"), first.PayloadSha256);
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(next, signature: otherKey.SignData(next,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pss)));
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(f.Payload(2, Hash("new"), Hash("incorrect-previous"))));
        var different = next.ToArray();
        different[^3] ^= 1;
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(different));
        Assert.Equal(1L, f.Read().CandidateSerial);
    }

    [Fact]
    public void CorruptionTruncationOrMissingJournalBlocksInspectionAndFurtherWrites()
    {
        using var f = new Fixture();
        f.Bootstrap();
        var first = f.Append(f.Payload(1, Hash("first"), new string('0', 64)));
        var complete = File.ReadAllBytes(f.PathName);

        File.WriteAllBytes(f.PathName, complete[..^1]);
        Assert.Throws<UnauthorizedAccessException>(() => f.Read());
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(f.Payload(2, Hash("second"), first.PayloadSha256)));
        File.WriteAllBytes(f.PathName, complete);
        var tampered = complete.ToArray();
        tampered[^8] ^= 1;
        File.WriteAllBytes(f.PathName, tampered);
        Assert.Throws<UnauthorizedAccessException>(() => f.Read());
        File.WriteAllBytes(f.PathName, complete);
        Assert.Equal(1L, f.Read().CandidateSerial);

        File.Delete(f.PathName);
        Assert.Throws<UnauthorizedAccessException>(() => f.Read());
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(f.Payload(2, Hash("second"), first.PayloadSha256)));
    }

    [Fact]
    public void FutureStaleNoncanonicalAndMissingSignatureAreRejected()
    {
        using var f = new Fixture();
        f.Bootstrap();
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(f.Payload(1, Hash("late"), new string('0', 64),
                issued: f.Now.AddMinutes(3))));
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(f.Payload(1, Hash("stale"), new string('0', 64),
                issued: f.Now.AddDays(-2))));
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(f.Payload(0, Hash("zero"), new string('0', 64))));
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(f.Payload(1, "invalid", new string('0', 64))));
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append(f.Payload(1, Hash("first"), new string('0', 64)),
                signature: []));
        var normal = f.Payload(1, Hash("first"), new string('0', 64));
        Assert.Throws<UnauthorizedAccessException>(() =>
            f.Append([.. normal, 0x00]));
        Assert.Equal(1L, f.Append(normal).CandidateSerial);
        Assert.Throws<UnauthorizedAccessException>(() => f.Read(now: f.Now.AddHours(25)));
    }

    [Fact]
    public async Task ConcurrentWriterCannotReplaceAlreadyAppendedSerial()
    {
        using var f = new Fixture();
        f.Bootstrap();
        var first = f.Append(f.Payload(1, Hash("initial"), new string('0', 64)));
        async Task<bool> Attempt(string candidate)
        {
            try
            {
                return await Task.Run(() =>
                    f.Append(f.Payload(2, Hash(candidate), first.PayloadSha256))
                        .ReviewStatus == "UNAPPROVED");
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }

        var accepted = await Task.WhenAll(Attempt("A"), Attempt("B"));
        Assert.Single(accepted, value => value);
        Assert.Equal(2L, f.Read().CandidateSerial);
    }

    [Fact]
    public void ReplayingOlderJournalBytesRevealsNeedForGenuineIndependentImmutableCustody()
    {
        using var f = new Fixture();
        f.Bootstrap();
        var first = f.Append(f.Payload(3, Hash("old-seal"), new string('0', 64)));
        var older = File.ReadAllBytes(f.PathName);
        f.Append(f.Payload(4, Hash("new-seal"), first.PayloadSha256));
        Assert.Equal(4L, f.Read().CandidateSerial);

        // Ordinary mutable files remain vulnerable to restore/rollback.
        // The synthetic old journal is still validly signed. This is
        // NON-AUTHORIZING and keeps #64 OPEN.
        File.WriteAllBytes(f.PathName, older);
        var replayed = f.Read();
        Assert.Equal("UNAPPROVED", replayed.ReviewStatus);
        Assert.Equal(3L, replayed.CandidateSerial);
    }
}
