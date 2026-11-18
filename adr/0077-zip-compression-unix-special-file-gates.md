# ADR 0077 — Deny unsupported ZIP compression and non-regular file metadata offline

Status: Accepted for **non-authorizing, offline pilot ZIP parser hardening only**, 2026-11-18. [#108](https://github.com/KeyserDSoze/TemporalMark/issues/108) child of [#17](https://github.com/KeyserDSoze/TemporalMark/issues/17), following ADR [0076](0076-offline-zip-structure-sha256-self-consistency.md).

## Baseline and threat

Reviewed ADR 0004/0074/0075/0076, exact source `tests/integration/verify_period_export.py`, `test_verify_period_export.py`, current `.github/workflows/ci.yml`, `TimestampRegistryService.ExportZipAsync`, `docs/OFFLINE_PERIOD_EXPORT_VERIFIER.md`, THREAT_MODEL, ROADMAP and COMPLIANCE. ZIP central-directory members include a **compression method** and optional Unix `external_attr` mode metadata. Python's [`zipfile.ZipInfo.compress_type`](https://docs.python.org/3/library/zipfile.html#zipfile.ZipInfo.compress_type) supports several formats; unsupported methods can fail with `NotImplementedError` during `ZipFile.open`. **Python's `NotImplementedError` already subclasses `RuntimeError`, which the existing verifier catches generically**; so an unknown method is already fail-closed at read time (not a demonstrated traceback leak). However, the verifier currently accepts **known but outside-profile** methods such as BZIP2, and it does not reject disallowed compression in metadata before starting decompression. It rejects Unix symlinks but does not explicitly reject Unix FIFO, device, socket or directory *mode* bits without a trailing slash. These should never represent a valid `manifest.json` or `tokens/{uuid}.tsr` **ordinary file** in the current .NET v1 exporter.

## Decision

1. Restrict each ZIP entry to `ZIP_STORED` (method 0) or `ZIP_DEFLATED` (method 8), the methods suitable for current .NET `ZipArchive` v1 files. Reject other methods *before reading* any entry; this is a v1 profile, not a claim all standard ZIP methods are unsafe.
2. For Unix `create_system == 3`, inspect `stat.S_IFMT(external_attr >> 16)`; accept 0 (some ZIP producers leave type unset) or `stat.S_IFREG`; reject symbolic link, FIFO, socket, block/character device and directory types **even without a slash in the name**. Existing `info.is_dir()` check remains mandatory for all host encodings. Do not extract archive members; restrict to exact expected manifest/TSR names.
3. Preserve max 80MiB outer ZIP, 8MiB manifest, 1MiB/TSR, 64MiB total DER, immutable checksum comparison, duplicate names and JSON key rejection, 100ns UTC, `Unverified` only, no network/third-party libs. Keep the existing `RuntimeError` exception boundary, which **already includes** `NotImplementedError`; a new separate catch would be redundant. The new allowlist rejects unsupported metadata earlier, before decompression (no raw path/body).
4. TDD: commit this ADR, then RED-first Python tests using real in-memory v1 ZIP, including a mutated **both local+central headers** unsupported compression code, Unix FIFO/socket/block/character/directory special metadata and *positive* ordinary stored/deflate archives; then minimal validator fix, runbook, threat and roadmap. Require full exact final documentation-inclusive main SHA 4/4 actual GitHub CI and tests before closing only #108. #107 has its own older exact-SHA CI gate and is closed separately, only if verified.

## Limits

This is a **ZIP metadata decoder allowlist**, not protection against an adversary coherently replacing both unsigned manifest and DER or omission of whole periods; not RFC3161 CMS signature validation, signer/CRL/eIDAS qualified status, trusted time UTC(k), WORM, signed custody, complete period evidence or CAB/AgID certification. No Azure/on-prem application differences or registrar V015/V016 changes. Parent #17/#15/#13 remain OPEN and pilot metadata remains `Unverified`.

## Reference

- [Python zipfile documentation](https://docs.python.org/3/library/zipfile.html)
- [Python stat file types](https://docs.python.org/3/library/stat.html)
