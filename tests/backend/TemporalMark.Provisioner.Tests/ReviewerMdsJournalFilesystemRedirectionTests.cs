using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using TemporalMark.Infrastructure.WebAuthn;
using Xunit;

namespace TemporalMark.Provisioner.Tests;

/// <summary>
/// ADR 0037 RED-first existing-link denial tests on Ubuntu Linux CI.
/// Link inspection is NOT atomic O_NOFOLLOW; a privileged host operator
/// can still change a path or replay the whole genuine signed journal.
/// </summary>
public sealed class ReviewerMdsJournalFilesystemRedirectionTests
{
    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static byte[] Event(string policy, long serial, string seal,
        string previousSha256, DateTimeOffset now) =>
        Encoding.ASCII.GetBytes(string.Join("\n",
        [
            "TEMPORALMARK-UNAPPROVED-SIGNED-FILE-HIGHWATER-EVENT-1",
            policy,
            serial.ToString(CultureInfo.InvariantCulture),
            seal,
            previousSha256,
            now.AddSeconds(-2).ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ""
        ]));

    [Fact]
    public void ExistingValidFileSymlinkIsNotAValidJournalEvenWithAuthenticSignature()
    {
        if (!OperatingSystem.IsLinux())
            return;

        var dir = Path.Combine(Path.GetTempPath(), "temporalmark-no-link-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            var policy = Hash("policy-" + Guid.NewGuid());
            using var key = RSA.Create(2048);
            var pin = Convert.ToHexString(SHA256.HashData(
                key.ExportSubjectPublicKeyInfo()));
            var now = DateTimeOffset.UtcNow;
            var target = Path.Combine(dir, "genuine.log");
            var alias = Path.Combine(dir, "alias.log");
            ReviewerMdsOfflineFileHighWaterJournal.BootstrapNewForTests(
                target, policy, pin);
            var first = Event(policy, 1, Hash("seal-1"), new string('0', 64), now);
            var valid = ReviewerMdsOfflineFileHighWaterJournal.AppendSignedForTests(
                target, policy, pin, key, first,
                key.SignData(first, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss), now);
            var intact = File.ReadAllBytes(target);
            File.CreateSymbolicLink(alias, target);

            // RED: before path hardening FileStream follows alias and
            // returns the genuinely signed positive test observation.
            Assert.Throws<UnauthorizedAccessException>(() =>
                ReviewerMdsOfflineFileHighWaterJournal.InspectLatest(
                    alias, policy, pin, key, now));

            var second = Event(policy, 2, Hash("seal-2"), valid.PayloadSha256, now);
            Assert.Throws<UnauthorizedAccessException>(() =>
                ReviewerMdsOfflineFileHighWaterJournal.AppendSignedForTests(
                    alias, policy, pin, key, second,
                    key.SignData(second, HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pss), now));
            Assert.Equal(intact, File.ReadAllBytes(target));
            Assert.Equal("UNAPPROVED",
                ReviewerMdsOfflineFileHighWaterJournal.InspectLatest(
                    target, policy, pin, key, now).ReviewStatus);
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public void SymlinkedAncestorDirectoryIsRejectedForBootstrapReadAndAppend()
    {
        if (!OperatingSystem.IsLinux())
            return;

        var root = Path.Combine(Path.GetTempPath(), "temporalmark-no-link-parent-" +
            Guid.NewGuid().ToString("N"));
        var actualDir = Path.Combine(root, "real");
        Directory.CreateDirectory(actualDir);
        try
        {
            var policy = Hash("policy-" + Guid.NewGuid());
            using var key = RSA.Create(2048);
            var pin = Convert.ToHexString(SHA256.HashData(
                key.ExportSubjectPublicKeyInfo()));
            var now = DateTimeOffset.UtcNow;
            var realPath = Path.Combine(actualDir, "journal.log");
            ReviewerMdsOfflineFileHighWaterJournal.BootstrapNewForTests(
                realPath, policy, pin);
            var first = Event(policy, 1, Hash("first"), new string('0', 64), now);
            ReviewerMdsOfflineFileHighWaterJournal.AppendSignedForTests(
                realPath, policy, pin, key, first,
                key.SignData(first, HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pss), now);
            var before = File.ReadAllBytes(realPath);
            var aliasDir = Path.Combine(root, "alias-parent");
            Directory.CreateSymbolicLink(aliasDir, actualDir);
            var redirected = Path.Combine(aliasDir, "journal.log");

            Assert.Throws<UnauthorizedAccessException>(() =>
                ReviewerMdsOfflineFileHighWaterJournal.InspectLatest(
                    redirected, policy, pin, key, now));
            var second = Event(policy, 2, Hash("second"),
                Convert.ToHexString(SHA256.HashData(first)), now);
            Assert.Throws<UnauthorizedAccessException>(() =>
                ReviewerMdsOfflineFileHighWaterJournal.AppendSignedForTests(
                    redirected, policy, pin, key, second,
                    key.SignData(second, HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pss), now));

            var newThroughLink = Path.Combine(aliasDir, "new-journal.log");
            Assert.Throws<UnauthorizedAccessException>(() =>
                ReviewerMdsOfflineFileHighWaterJournal.BootstrapNewForTests(
                    newThroughLink, policy, pin));
            Assert.False(File.Exists(Path.Combine(actualDir, "new-journal.log")));
            Assert.Equal(before, File.ReadAllBytes(realPath));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void DanglingSymlinkCannotBeUsedForBootstrapOrReadAndNeverCreatesTarget()
    {
        if (!OperatingSystem.IsLinux())
            return;

        var root = Path.Combine(Path.GetTempPath(), "temporalmark-no-link-dangling-" +
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var policy = Hash("policy-" + Guid.NewGuid());
            using var key = RSA.Create(2048);
            var pin = Convert.ToHexString(SHA256.HashData(
                key.ExportSubjectPublicKeyInfo()));
            var target = Path.Combine(root, "missing-target.log");
            var alias = Path.Combine(root, "dangling-link.log");
            File.CreateSymbolicLink(alias, target);
            Assert.Throws<UnauthorizedAccessException>(() =>
                ReviewerMdsOfflineFileHighWaterJournal.BootstrapNewForTests(
                    alias, policy, pin));
            Assert.Throws<UnauthorizedAccessException>(() =>
                ReviewerMdsOfflineFileHighWaterJournal.InspectLatest(
                    alias, policy, pin, key, DateTimeOffset.UtcNow));
            Assert.False(File.Exists(target));
            // File.Exists on a dangling link can be platform-dependent.
            // The link itself still exists and must not become the journal.
            Assert.NotNull(new FileInfo(alias).LinkTarget);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }
}
