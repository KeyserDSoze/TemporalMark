# Offline consistency check of a TemporalMark period export (#107)

**UNQUALIFIED PILOT ONLY. This checker is NOT a signature verifier,
legal preservation system, trusted witness or QTSP qualification check.**
See [ADR 0076](../adr/0076-offline-zip-structure-sha256-self-consistency.md)
and still-open [parent #17](https://github.com/KeyserDSoze/TemporalMark/issues/17).

## Run without a server, cloud login or network

After a tenant administrator downloads the export ZIP through the
authenticated, audited `GET /api/v1/stamps/export` endpoint, run:

```sh
python3 tests/integration/verify_period_export.py /path/to/temporalmark-period.zip
```

The CLI uses **Python 3 standard library only**; no third-party packages,
TSA/API requests, SQL connections, certificates, HSM keys or outbound
network. A successful command reports only a count and:

```
LOCAL ZIP STRUCTURE/SHA256 CONSISTENT: N receipts. NOT signed, qualified, complete-period proof or RFC3161 signature validation.
```

It exits 0 for a structurally/hash-consistent **current**
`temporalmark-period-export-v1` archive, exits nonzero on mismatch
or unsupported input and does **not** print tokens, tenant IDs,
document-imprint digests, provider URLs, archive paths or internal exception
messages. Do not relay private archive contents to third-party validators.

## What is checked

- Exactly one `manifest.json`, supported v1 schema and exactly the
  expected `tokens/{lowercase-UUID-without-hyphens}.tsr` members;
  no duplicate/extra/missing ZIP names, symlink/directory/encrypted members,
  filesystem traversal or extraction. Manifest JSON duplicate keys and
  unknown schemas are refused, not silently overwritten.
- ZIP member compression is limited to **STORE (method 0)** and
  **DEFLATE (method 8)**, the v1 export-compatible methods. BZIP2,
  LZMA, unknown and other methods are rejected **before** reading a
  member, even if the local Python installation could decompress it.
  On Unix-origin entries, external file-type bits must identify an
  ordinary file or omit the type; FIFO, socket, character/block device,
  symbolic link and directory metadata are all rejected. No member
  is extracted or executed. The verifier also compares the **local ZIP header's** method and general-purpose flags against the **central-directory** values for each member before decompression. Python's default ZIP reader checks names but does not itself bind these fields: an altered local method can disagree with an otherwise valid central entry without changing manifest/DER hashes. Mismatches fail closed after a bounded 30-byte local-header read, with no path output. See [ADR 0078](../adr/0078-zip-local-central-header-method-flag-binding.md) and [#109](https://github.com/KeyserDSoze/TemporalMark/issues/109). See also [ADR 0077](../adr/0077-zip-compression-unix-special-file-gates.md)
  and focused [#108](https://github.com/KeyserDSoze/TemporalMark/issues/108).
- Organization identifier is a canonical nonempty UUID. Manifest count
  matches entries and the ZIP. Each record ID is canonical and unique,
  with a correctly mapped member path. Issuance times are explicit UTC
  and within the inclusive-from/exclusive-to manifest period.
  DateTimeOffset fractional seconds are compared at full **100ns
  (seven-digit)** precision.
- Empty TSR/DER members are refused even if their declared SHA-256 matches the empty byte string; the producer's `TimestampRecord.Validate()` already enforces this.
- Every record declares the SHA-256 OID and a canonical 32-byte SHA-256
  message imprint Base64, with nonempty provider/policy strings. The
  **actual raw DER member bytes** match the manifest's full hexadecimal
  `TokenSha256Hex`; the ZIP CRC is also exercised by reading members.
- The current pilot's `validationState` must be **`Unverified`**;
  a forged `VerifiedQualifiedExternal`/`VerifiedQualifiedOwn` state
  cannot become trusted simply by appearing in an unsigned JSON file.
- Defense-in-depth limits: at most **10,000 token members**, each
  uncompressed DER **1 MiB**, total uncompressed DER **64 MiB**,
  `manifest.json` uncompressed **8 MiB**, and outer ZIP file
  **80 MiB**. ZIP announced sizes are checked *and* actual
  decompression reads are capped. No archive member is extracted.

## Trust boundary and residual risks

**Two files edited together can pass.** The manifest is **not digitally
signed, authenticated, notarized, independently witnessed or stored in
WORM**. An attacker able to replace both a DER member and its declared
SHA-256 digest can create another internally consistent archive. This
utility does not parse RFC3161/CMS, check a timestamp signature or nonce,
authenticate a signer certificate, evaluate CRL or the historical EU
Trusted List, validate UTC(k) accuracy, verify GDPR retention/holds,
or prove that **every** record in the requested period was exported.
A string `Unverified` is still just metadata, never trust proof.

Keep a separate authenticated source of custody, signed manifests,
durable high-water witnesses, WORM/object-lock with legal hold,
full RFC3161 trust and complete/streaming export protocols as open
deliverables #17/#15/#13. The registry API remains tenant-bound and
the WebAuthn V015/V016 registrar issuance stop line remains frozen.
The same exported v1 format is used on-prem and on Azure.

## Development / regression tests

```sh
python3 -m unittest discover -s tests/integration -p 'test_verify_period_export.py' -v
```

These generate disposable in-memory ZIP fixtures; **not live qualified
TSA tokens**. Tests cover genuine current v1 shape, empty export,
DER/hash tampering, duplicate ZIP names and JSON keys, missing/extra
members, path-traversal/symlink, duplicate IDs and bad count, out-of-range
or sub-microsecond UTC timestamps, noncanonical Base64,
unsupported qualified-status claims, empty DER members, oversized compressed members and generic/no-secret CLI success/failure output. Actual TDD RED: [Actions 44287937173](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44287937173/attempts/1) ran 15 offline tests and failed only the new empty-DER guard before the fix.
The pipeline invokes them before the .NET build using the existing
read-only `backend` job.

Focused #108 adversarial unit tests additionally mutate **both local and
central ZIP compression method headers** to an unknown value, test
supported-by-Python but disallowed-by-v1 BZIP2, fake Unix FIFO/socket/
device/directory modes and the valid STORE/DEFLATE ordinary-file paths.
A malformed test fixture previously failed before invoking the verifier
([CI 44290472692](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44290472692/attempts/1),
19/20 tests), so the fixture was corrected before treating this
new coverage as valid. Do not report the final #108 tests GREEN until
its own exact documentation-inclusive main HEAD and four core CI jobs pass.

Sources: [Python `zipfile`](https://docs.python.org/3/library/zipfile.html),
[Python `json` duplicate-key hook](https://docs.python.org/3/library/json.html),
[ADR 0004](../adr/0004-evidence-time-and-retention.md) and
[ADR 0074](../adr/0074-registry-page-export-integrity-and-unique-ids.md).
