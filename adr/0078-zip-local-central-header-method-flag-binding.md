# ADR 0078 — Bind offline ZIP central-directory metadata to each local header

Status: Accepted for **offline, non-authorizing v1 archive consistency hardening**, 2026-11-18. [#109](https://github.com/KeyserDSoze/TemporalMark/issues/109), child of still-open evidence #17; follows ADR [0076](0076-offline-zip-structure-sha256-self-consistency.md) and [0077](0077-zip-compression-unix-special-file-gates.md).

## Baseline and observed ambiguity

Reviewed ADR 0004/0076/0077, real `tests/integration/verify_period_export.py`, `test_verify_period_export.py`, `.github/workflows/ci.yml`, `TimestampRegistryService.ExportZipAsync` and the offline operator guide, threat model and roadmap. ZIP contains separate **local file headers** and a **central directory**. The v1 checker currently consults the central `ZipInfo.compress_type`, flags, names and Unix modes, and Python's `ZipFile.open` checks the local filename but **does not require the local compression-method field to match the central-directory method**. The underlying behavior was reproduced with Python standard-library ZIP: a DEFLATE archive with its local method field overwritten to 99 (central remains 8) is still read successfully by `ZipFile.read`. Two contradictory descriptions could be passed onward as a supposedly consistent archive without modifying the bytes, CRC, SHA-256 or manifest.

This is an **archive ambiguity** rather than evidence that a signature was forged or that qualified timestamps were issued.

## Decision

1. Prior to parsing any manifest or decompressing any members, inspect the **first 30 bytes of each central entry's local file header** via `ZipInfo.header_offset`, respecting the existing at-most-80MiB outer ZIP and at-most-10,001 member limits. Require exact local header magic `PK\\x03\\x04` and that its 16-bit compression method equals the central `ZipInfo.compress_type`, itself constrained by ADR 0077 to STORE(0) or DEFLATE(8).
2. Require the local **general-purpose 16-bit flags** to equal the central `ZipInfo.flag_bits`. This rejects central/local encryption discrepancies, mismatched data-descriptor interpretation and UTF-8 flag ambiguity rather than guessing which representation is authoritative. Retain existing explicit no-encrypted-members rule. Do not traverse any filename as a filesystem path, and never extract files.
3. If a local header is missing, truncated, references a negative/out-of-archive offset, mismatches magic or flags/method, or fails a ZIP seek/read, return the existing generic `ExportVerificationError`/CLI nonzero without dumping raw token, tenant, hash, path or URL. Keep all current v1 name/layout/size/UTC/hash and pilot `Unverified` checks. No new dependencies, API, DB schema or cloud-specific code.
4. **TDD:** commit ADR first; add source-only RED-first Python fixtures with a **valid manifest/DER** but local method 99/central 8 (for both manifest and token separately), and local-only encrypted/other flag differences; positive regular STORE/DEFLATE preserved. Tests must mutate exact binary ZIP fields, not incorrectly escaped Python byte literals. Follow with minimal verifier implementation and docs. Only close after independently verified **exact final documentation-inclusive main SHA 4/4 GitHub CI**, linked job statuses, Python test count and .NET tests.
5. This stricter **v1 consistency profile** may reject exotic otherwise-readable ZIP variants. It does not authenticate the unsigned manifest or detect coherent edits of both DER and its hash; cannot verify RFC3161/CMS, historic EU Trusted List, qualified QTSP, UTC(k), WORM custody, complete-period exports or CAB/AgID certification. Parents #17/#15/#13 and V015/V016 registrar interlocks remain OPEN; all pilot evidence stays `Unverified`.

## Reference

- [Python zipfile documentation](https://docs.python.org/3/library/zipfile.html)
- [PKWARE ZIP APPNOTE format](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
