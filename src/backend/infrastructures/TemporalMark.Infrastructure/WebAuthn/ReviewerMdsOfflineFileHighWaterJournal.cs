using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace TemporalMark.Infrastructure.WebAuthn;

/// <summary>
/// NON-AUTHORIZING synthetic signed *file* high-water observation.
/// A normal file and caller-selected test SPKI pin are NOT an independently
/// immutable witness, official FIDO trust or any credential authority.
/// </summary>
public sealed record ReviewerMdsFileHighWaterObservation(
    string ReviewStatus, string PolicyStage, long CandidateSerial,
    string SealSha256, string PayloadSha256);

/// <summary>
/// ADR 0036 / #67: offline, bounded, signed and hash-linked disk journal.
/// The test-only file is deliberately separate from PostgreSQL; it is still
/// rollback-able by a privileged OS/storage/backup administrator.
/// NO production/API/CLI/SQL/credential enrollment call site is provided.
/// </summary>
public static class ReviewerMdsOfflineFileHighWaterJournal
{
    private const string HeaderDomain =
        "TEMPORALMARK-UNAPPROVED-SIGNED-FILE-HIGHWATER-1";
    private const string EventDomain =
        "TEMPORALMARK-UNAPPROVED-SIGNED-FILE-HIGHWATER-EVENT-1";
    private const string Status = "TEST_FILE_HIGH_WATER_NO_INDEPENDENT_CUSTODY";
    private const int MaximumFileBytes = 131072;
    private const int MaximumPayloadBytes = 512;
    private const int MaximumEvents = 128;
    private static readonly TimeSpan MaximumLatestAge = TimeSpan.FromHours(24);
    private static readonly string GenesisHash = new('0', 64);

    /// <summary>
    /// Explicit TEST bootstrap only. Never create on ordinary lookup/write,
    /// truncate existing evidence, initialize a missing file on failure or
    /// provision production directories or trust anchors.
    /// </summary>
    public static void BootstrapNewForTests(
        string? journalPath, string? sourcePolicySha256,
        string? testAuthoritySpkiSha256)
    {
        if (string.IsNullOrWhiteSpace(journalPath) ||
            !Path.IsPathFullyQualified(journalPath) ||
            !IsSha256(sourcePolicySha256) ||
            !IsSha256(testAuthoritySpkiSha256))
            throw Denied();

        try
        {
            RejectFilesystemRedirection(journalPath, allowMissingLeaf: true);
            var header = Encoding.ASCII.GetBytes(
                HeaderDomain + "\n" + sourcePolicySha256 + "\n" +
                testAuthoritySpkiSha256 + "\n");
            using var file = new FileStream(journalPath, FileMode.CreateNew,
                FileAccess.Write, FileShare.None);
            RejectFilesystemRedirection(journalPath, allowMissingLeaf: false);
            file.Write(header);
            file.Flush(flushToDisk: true);
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            throw Denied();
        }
    }

    /// <summary>
    /// Append a PRE-SIGNED event from a separately held test RSA key. The
    /// journal NEVER receives private key material or creates signatures.
    /// Every previous entry is independently verified under an exclusive
    /// stream before any write; a broken/partial chain cannot be repaired.
    /// </summary>
    public static ReviewerMdsFileHighWaterObservation AppendSignedForTests(
        string? journalPath,
        string? sourcePolicySha256,
        string? expectedTestAuthoritySpkiSha256,
        RSA? testAuthorityPublicKey,
        byte[]? originalSignedEvent,
        byte[]? detachedSignature,
        DateTimeOffset nowUtc)
    {
        ValidateArguments(journalPath, sourcePolicySha256,
            expectedTestAuthoritySpkiSha256, testAuthorityPublicKey, nowUtc);
        if (originalSignedEvent is null || detachedSignature is null)
            throw Denied();

        try
        {
            RejectFilesystemRedirection(journalPath!, allowMissingLeaf: false);
            using var file = new FileStream(journalPath!, FileMode.Open,
                FileAccess.ReadWrite, FileShare.None);
            RejectFilesystemRedirection(journalPath!, allowMissingLeaf: false);
            var existing = InspectFile(file, sourcePolicySha256!,
                expectedTestAuthoritySpkiSha256!, testAuthorityPublicKey!, nowUtc,
                allowEmpty: true);
            if (existing.Count >= MaximumEvents)
                throw Denied();

            var current = ValidateSignedEvent(originalSignedEvent,
                detachedSignature, sourcePolicySha256!,
                testAuthorityPublicKey!, existing.Last?.PayloadSha256 ?? GenesisHash,
                existing.Last?.CandidateSerial ?? 0L,
                existing.LastObservedSeconds, nowUtc);

            var encoded = Encoding.ASCII.GetBytes(
                Convert.ToBase64String(originalSignedEvent) + "|" +
                Convert.ToBase64String(detachedSignature) + "\n");
            if (file.Length + encoded.Length > MaximumFileBytes)
                throw Denied();
            file.Position = file.Length;
            file.Write(encoded);
            // Asks OS to flush file data and metadata. Does NOT provide
            // immutable, trusted remote/offsite custody or physical-DR proof.
            file.Flush(flushToDisk: true);
            return current.Observation;
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            throw Denied();
        }
    }

    /// <summary>
    /// Fail closed on no file, empty file, incomplete line, changed header,
    /// invalid RSA signature, malformed chain, stale last event or key pin.
    /// Test-only latest hash; never an authority to activate a credential.
    /// </summary>
    public static ReviewerMdsFileHighWaterObservation InspectLatest(
        string? journalPath,
        string? sourcePolicySha256,
        string? expectedTestAuthoritySpkiSha256,
        RSA? testAuthorityPublicKey,
        DateTimeOffset nowUtc)
    {
        ValidateArguments(journalPath, sourcePolicySha256,
            expectedTestAuthoritySpkiSha256, testAuthorityPublicKey, nowUtc);
        try
        {
            RejectFilesystemRedirection(journalPath!, allowMissingLeaf: false);
            using var file = new FileStream(journalPath!, FileMode.Open,
                FileAccess.Read, FileShare.None);
            RejectFilesystemRedirection(journalPath!, allowMissingLeaf: false);
            return InspectFile(file, sourcePolicySha256!,
                expectedTestAuthoritySpkiSha256!, testAuthorityPublicKey!, nowUtc,
                allowEmpty: false).Last?.Observation ?? throw Denied();
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            throw Denied();
        }
    }

    /// <summary>
    /// Best-effort rejection of OBSERVABLE symbolic links, junctions and
    /// reparse points in the final path and each directory ancestor.
    /// This is not O_NOFOLLOW/openat2 or atomic protection against a hostile
    /// administrator replacing the path between checks, hard links, bind
    /// mounts, a backed-up journal, or independently pinned signer custody.
    /// </summary>
    private static void RejectFilesystemRedirection(
        string path, bool allowMissingLeaf)
    {
        if (!Path.IsPathFullyQualified(path) ||
            !string.Equals(Path.GetFullPath(path), path, StringComparison.Ordinal))
            throw Denied();

        var directoryPath = Path.GetDirectoryName(path);
        if (string.IsNullOrEmpty(directoryPath))
            throw Denied();

        for (var parentPath = directoryPath; parentPath is not null;
             parentPath = Path.GetDirectoryName(parentPath))
        {
            var parent = new DirectoryInfo(parentPath);
            parent.Refresh();
            if (!parent.Exists ||
                parent.LinkTarget is not null ||
                (parent.Attributes & FileAttributes.ReparsePoint) != 0 ||
                (parent.Attributes & FileAttributes.Directory) == 0)
                throw Denied();
        }

        var leaf = new FileInfo(path);
        leaf.Refresh();
        if (leaf.LinkTarget is not null)
            throw Denied();
        if (leaf.Exists)
        {
            if ((leaf.Attributes & (FileAttributes.ReparsePoint |
                                     FileAttributes.Directory)) != 0)
                throw Denied();
        }
        else if (!allowMissingLeaf || Directory.Exists(path))
        {
            throw Denied();
        }
    }

    private static void ValidateArguments(
        string? path, string? policy, string? pin, RSA? key,
        DateTimeOffset nowUtc)
    {
        if (string.IsNullOrWhiteSpace(path) ||
            !Path.IsPathFullyQualified(path) ||
            !IsSha256(policy) || !IsSha256(pin) ||
            key is null || nowUtc.Offset != TimeSpan.Zero ||
            key.KeySize is < 2048 or > 4096)
            throw Denied();

        try
        {
            if (!CryptographicOperations.FixedTimeEquals(
                SHA256.HashData(key.ExportSubjectPublicKeyInfo()),
                Convert.FromHexString(pin!)))
                throw Denied();
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            throw Denied();
        }
    }

    private static ValidatedJournal InspectFile(
        FileStream file, string policy, string pin,
        RSA authority, DateTimeOffset nowUtc, bool allowEmpty)
    {
        if (file.Length is < 130 or > MaximumFileBytes)
            throw Denied();

        file.Position = 0;
        var buffer = new byte[checked((int)file.Length)];
        file.ReadExactly(buffer);
        if (!CanonicalAscii(buffer))
            throw Denied();

        var lines = Encoding.ASCII.GetString(buffer).Split('\n');
        if (lines.Length < 4 || lines[^1] != "" ||
            lines[0] != HeaderDomain ||
            lines[1] != policy || lines[2] != pin)
            throw Denied();

        var count = lines.Length - 4;
        if (count < 0 || count > MaximumEvents || (!allowEmpty && count == 0))
            throw Denied();

        string previousHash = GenesisHash;
        long previousSerial = 0;
        long previousObserved = 0;
        SignedEvent? latest = null;

        for (var i = 0; i < count; i++)
        {
            var parts = lines[i + 3].Split('|');
            if (parts.Length != 2 || parts[0].Length == 0 ||
                parts[1].Length == 0)
                throw Denied();

            var payload = Convert.FromBase64String(parts[0]);
            var signature = Convert.FromBase64String(parts[1]);
            if (Convert.ToBase64String(payload) != parts[0] ||
                Convert.ToBase64String(signature) != parts[1])
                throw Denied();

            latest = ValidateSignedEvent(payload, signature, policy,
                authority, previousHash, previousSerial, previousObserved,
                nowUtc);
            previousHash = latest.PayloadSha256;
            previousSerial = latest.CandidateSerial;
            previousObserved = latest.ObservedSeconds;
        }

        if (latest is not null &&
            nowUtc.ToUnixTimeSeconds() - latest.ObservedSeconds >
                MaximumLatestAge.TotalSeconds)
            throw Denied();

        return new ValidatedJournal(latest, count, previousObserved);
    }

    private static SignedEvent ValidateSignedEvent(
        byte[] payload, byte[] signature, string policy,
        RSA authority, string expectedPreviousHash,
        long previousSerial, long previousObserved, DateTimeOffset nowUtc)
    {
        if (payload.Length is < 180 or > MaximumPayloadBytes ||
            signature.Length != authority.KeySize / 8 ||
            !CanonicalAscii(payload) ||
            !authority.VerifyData(payload, signature,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            throw Denied();

        var fields = Encoding.ASCII.GetString(payload).Split('\n');
        if (fields.Length != 7 || fields[^1] != "" ||
            fields[0] != EventDomain || fields[1] != policy ||
            !CanonicalPositiveLong(fields[2], out var candidateSerial) ||
            candidateSerial <= previousSerial ||
            !IsSha256(fields[3]) ||
            !IsSha256(fields[4]) ||
            !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(fields[4]),
                Convert.FromHexString(expectedPreviousHash)) ||
            !CanonicalPositiveLong(fields[5], out var observedSeconds) ||
            observedSeconds < previousObserved ||
            observedSeconds > nowUtc.ToUnixTimeSeconds() ||
            nowUtc.ToUnixTimeSeconds() - observedSeconds >
                MaximumLatestAge.TotalSeconds)
            throw Denied();

        var payloadSha = Convert.ToHexString(SHA256.HashData(payload));
        var observation = new ReviewerMdsFileHighWaterObservation(
            "UNAPPROVED", Status, candidateSerial, fields[3], payloadSha);
        return new SignedEvent(observation, observedSeconds);
    }

    private static bool CanonicalAscii(byte[] bytes)
    {
        if (bytes.Length == 0 || bytes[^1] != 10)
            return false;
        return bytes.All(c => c == 10 || c is >= 33 and <= 126);
    }

    private static bool IsSha256(string? value) =>
        value is { Length: 64 } &&
        value.All(c => c is (>= 'A' and <= 'F') or (>= '0' and <= '9'));

    private static bool CanonicalPositiveLong(string raw, out long value) =>
        long.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture,
            out value) && value > 0 &&
        raw == value.ToString(CultureInfo.InvariantCulture);

    private static UnauthorizedAccessException Denied() =>
        new("Unapproved or invalid offline signed file high-water journal.");

    private sealed record SignedEvent(
        ReviewerMdsFileHighWaterObservation Observation,
        long ObservedSeconds)
    {
        public long CandidateSerial => Observation.CandidateSerial;
        public string PayloadSha256 => Observation.PayloadSha256;
    }

    private sealed record ValidatedJournal(
        SignedEvent? Last, int Count, long LastObservedSeconds);
}
