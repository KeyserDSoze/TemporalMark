# ADR 0037 — Best-effort rejection of journal filesystem links (not atomic no-follow security)

Status: **accepted for isolated non-authorizing file-path regression only**, 2026-11-16. Focused [#68](https://github.com/KeyserDSoze/TemporalMark/issues/68), child of open #64/#61/#57. Reviewed ADR 0032–0036, `ReviewerMdsOfflineFileHighWaterJournal`, existing temp-file and real full logical PostgreSQL restore tests and `docs/MDS_CRL_SIGNED_FILE_HIGH_WATER_JOURNAL.md`.

## Problem and boundaries

The journal created in ADR 0036 is an ordinary host-local mutable file, opened by a caller-selected absolute path using `FileStream`. OS file-opening ordinarily follows symbolic links and directory symlinks/junctions/reparse points. An operator with control over the path could redirect bootstrap/read/append to another path or existing previously signed journal. This is a preventable accidental/direct redirection hazard. Explicitly reject known links and directory reparse points and fail closed rather than accidentally traversing them.

**Critical:** .NET `FileInfo.LinkTarget`, `DirectoryInfo.LinkTarget`, `FileAttributes.ReparsePoint` and `FileStream` do not, together, provide a race-free `openat2`/O_NOFOLLOW, a mount-namespace lock, a secure filesystem, immutable latest pointer, verified hard-link count or symlink/rename safety against an adversary who can change the path between checks. We only catch **already-existing/observable** filesystem redirections. Before or after checking a path does not eliminate TOCTOU. A privileged host/backup admin can still replace the whole journal or roll back the file, and externally supplied test key/pin can still be substituted. Do not describe the result as production symlink safety, independent immutable custody, attested monotonicity, or FIDO CRL/JWS signer trust.

## Decision

1. Add a private **test-only** `RejectFilesystemRedirection` helper to `ReviewerMdsOfflineFileHighWaterJournal`. It checks a fully qualified path, all existing parent directories back to the root and the leaf. Parent directories must exist, be true directories, and not report `LinkTarget` or `FileAttributes.ReparsePoint`. The leaf, when present, must be a regular file and not a symlink/junction/reparse point. In bootstrap, absence of the leaf is allowed only for explicit `FileMode.CreateNew`; ordinary read/append still require an existing leaf. Dangling known links must be rejected. File attributes and path checks should fail closed on I/O or permission errors.
2. Call this check **before** create/open and **after acquiring the exclusive stream before any read or append**. Keep existing RSA-PSS signatures, hash-linked serials, entire-file validation, expiry, explicit bootstrap, `FileShare.None` and `Flush(true)` unchanged. Do not invent an independent key, allow a normal read to bootstrap, activate a credential or grant SQL access.
3. TDD: commit ADR before RED tests; on Ubuntu CI create a real valid signed target file, then an absolute symbolic link to it, and a symlink-directory parent pointing at it. Bootstrap via symlink must refuse and preserve target bytes; inspect and append must refuse symlink paths even though target contents/signatures are valid. Test a dangling symbolic link and forbidden directory as leaf, legitimate normal file pass. On other OS, tests can be skipped only when the OS denies link creation (no false positive claims).
4. Explicitly document that a path-replacement **race after validation**, hardlinks, bind mounts, O_NOFOLLOW/handle identity, container escape, host owner compromise and independent immutable witness custody remain open #64. No SQL migration, V015/V016 grant, registrar CLI or runtime wiring; all observations always `UNAPPROVED`. Parent #64/#61/#57/#55/#53/#44/#50/#46/#38 remain OPEN. Exact final `main` SHA four-job GitHub Actions green before closing only #68.

## Sources

- [.NET 10 FileSystemInfo.LinkTarget](https://learn.microsoft.com/en-us/dotnet/api/system.io.filesysteminfo.linktarget?view=net-10.0)
- [.NET 10 FileAttributes.ReparsePoint](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileattributes?view=net-10.0)
- [ADR 0036](0036-fail-closed-test-signed-file-high-water-journal.md)
