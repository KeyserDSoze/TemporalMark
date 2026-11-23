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


## Whole-file v1 ZIP envelope binding (#155 / ADR 0120)

This offline CLI now rejects otherwise Python-`zipfile`-readable period exports with **opaque data prepended before the first ZIP member** (self-extracting/polyglot wrapper), **any bytes after the ZIP end-of-central-directory** (opaque payload or NUL padding), and non-v1 central-directory gaps or ZIP64/multi-disk/comment layouts. A valid `temporalmark-period-export-v1` created by the **current memory-backed .NET ZIP producer** starts at byte zero with `PK\\x03\\x04`, ends with the **22-byte classic EOCD `PK\\x05\\x06`**, contains no EOCD comment and has single-disk entry counts and central-directory offset+size exactly matching the archive and member count. The parser reads only **4+22 fixed bytes** before decompressing anything; the existing ≤80MiB total input, ≤8MiB manifest, ≤1MiB/TSR and ≤64MiB total DER guards remain. This deliberately strict v1 format does **not** support ZIP stubs, ZIP64, extra trailers or exotic otherwise-readable ZIP profiles; use a reviewed new schema/ADR for any format change rather than suppressing the gate.

Test-first [real Python RED 44966967378](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44966967378) proved **5 missing-denial failures / 24 previously passing cases / 29 total** on unchanged manifest/DER/CRC with prefixed/trailing bytes that stock Python ZipFile could read; an exact one/zero-receipt ZIP remained accepted. See [ADR 0120](../adr/0120-offline-period-zip-strict-envelope.md)/[#155](https://github.com/KeyserDSoze/TemporalMark/issues/155). The CLI still prints only a generic error on rejected inputs, never a tenant ID, token, file path or appended payload. This is **local, unsigned container consistency only**, not a verified TSA signature, qualified status, proof of full-period coverage, externally held witness or WORM legal retention; parents #17/#15/#13 remain OPEN.


## Alignment with pilot API registry states (#156)

The standalone verifier already denies **all** `validationState` values other than `Unverified` (ADR 0076). [ADR 0121](../adr/0121-pilot-registry-unsupported-validation-state-read-gate.md)/[#156](https://github.com/KeyserDSoze/TemporalMark/issues/156) now align the **server-side registry Page/Search/Receipt/Export** boundaries with this pilot-only rule so a database row with valid DER and SHA256 but an unsupported `VerifiedQualifiedExternal`, `VerifiedQualifiedOwn`, `VerifiedNonQualified` or `AffectedByIncident` label is rejected **before constructing any downloadable v1 archive or returning read metadata**. [real .NET Business TDD RED 44970125295](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44970125295): 16 actual .NET Business cases failed before source implementation despite valid DER/SHA and tenant, proving the omitted read gate. No change to the ZIP structure, offline 29-test suite, SHA256-only checker or legal status. The read boundary is not an RFC3161 CMS signature verifier, historical QTSP trusted-list status, independent signatory or signed complete-period evidence.


## CRC32 and compressed/uncompressed length header binding (#164 / ADR 0122)

The **current seekable .NET `MemoryStream` v1 ZIP producer** records each member's CRC32, compressed byte length and uncompressed byte length in its ordinary local file header. Python's generic `zipfile` uses central-directory metadata to decompress and check CRC; an archive with a changed **local-only** CRC32 or length may still read correctly and satisfy the previous manifest/TSR hash checks. The offline tool now compares **all three local 32-bit fields** with the central `ZipInfo` values for `manifest.json` and **every** TSR, alongside previously checked flags and compression method. It reuses one fixed **30-byte read** for each member before any JSON or DER decompression. The narrow v1 profile also denies general-purpose ZIP flag **bit 3** (streaming data descriptors); a future non-seekable exporter must introduce and test a separately reviewed archive format instead of silently weakening this contract.

[ADR 0122](../adr/0122-offline-v1-local-crc-and-size-directory-binding.md) and [issue #164](https://github.com/KeyserDSoze/TemporalMark/issues/164) record tests first: real [GitHub Actions RED 45005035684](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45005035684/attempts/1), **32 tests total / eight genuine missing-denial failures / 24 passes**, covering local-only CRC/compressed/uncompressed sizes on both archive members, CLI generic-error redaction and an otherwise readable bit-3 archive. Minimal source fix [`26aa416`](https://github.com/KeyserDSoze/TemporalMark/commit/26aa416968fd3b1b736060420114a97c0267b22a) added local comparisons only after real RED. The exact **final documentation-inclusive** GitHub GREEN must be independently confirmed. This is only internal binary-archive consistency: no manifest signature, RFC3161/CMS trust, QTSP/EUTL qualification, period completeness, signed independent WORM evidence or legally approved retention.


## Reject internal unreferenced ZIP gaps (#165 / ADR 0123)

The strict v1 physical envelope (ADR 0120) verifies the outer ZIP starts/ends correctly, and ADR 0122 binds local CRC32/size metadata to the central directory. Neither alone excludes an **opaque interval between the declared compressed member contents and the next local header or central directory**. Python's ordinary `zipfile` accepts such gaps with adjusted ZIP offsets and still reads intact members. The **current seekable .NET memory-backed v1 exporter** instead writes the ordinary local header, filename/extra, compressed bytes and immediately the next member/central directory, with no streaming descriptor (general-purpose bit 3 is already denied).

For every current v1 archive, the offline checker now sorts the bounded local header offsets and requires each member's declared physical end (`local header offset + 30 + local name length + local extra length + compressed size`) to **equal the next member's local header offset**, with the first member at byte 0 and the last ending **exactly** at the verified start of the central directory. It reads no additional compressed member bytes while checking the layout; failures occur **before any JSON or TSR decompression** and the CLI reports a generic denial without private values. Current zero- and one-receipt STORE/DEFLATE archives remain within the accepted profile. More exotic/streaming formats require an independently reviewed version, not a relaxed v1 guard.

[ADR 0123](../adr/0123-offline-v1-zip-contiguous-local-member-layout.md) / [issue #165](https://github.com/KeyserDSoze/TemporalMark/issues/165): tests-only [`018a6a5`](https://github.com/KeyserDSoze/TemporalMark/commit/018a6a5a67b08cc66074ad5e65667e74e69f74eb), genuine [GitHub RED 45014471651](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45014471651/attempts/1) **34 test methods: four missing-denial failures / 30 passes** across inter-member/last-to-central/empty-export overlays and CLI. Only afterward fixed by [`8765302`](https://github.com/KeyserDSoze/TemporalMark/commit/876530262aeb77fa7e66942cc2a4ab8e74f33bff). Do not infer final GREEN before exact docs-inclusive GitHub CI. This is **unsigned local ZIP consistency only**, not CMS/RFC3161 signature verification, QTSP/EUTL qualification, WORM/independent custody or full-period completeness.


## Producer and checker JSON/ZIP budget alignment (#166 / ADR 0124)

Before #166, the `.NET` pilot exporter applied only count/raw-DER input caps and could produce a **compressed** v1 ZIP containing **more than 8 MiB uncompressed manifest JSON**. This offline verifier correctly rejects such ZIPs, but the API could nevertheless offer them for download. The producer now pre-serializes its **actual JSON bytes** into an at-most-8-MiB bounded stream before constructing the ZIP, preserving exact data and v1 keys while refusing malformed-size requests with the existing HTTP 413 mapping; also limits the returned physical ZIP to **80 MiB**. No `string.Length` approximation: Unicode escaping is measured in serialized bytes, not C# code units. The verifier's independent existing 8 MiB uncompressed manifest, 80 MiB archive, 1 MiB/TSR and 64 MiB aggregate DER checks remain essential for copied/untrusted archives.

[Issue #166](https://github.com/KeyserDSoze/TemporalMark/issues/166) / [ADR 0124](../adr/0124-bounded-v1-manifest-and-zip-export-output.md); genuine [.NET10 Business TDD RED 45052741202](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45052741202/attempts/1) 3 missing size rejections / 281 passes on unmodified DER/hash/UTC and a successful large-but-under-budget fixture. This **does not** mean the ZIP is signed, complete for a period, WORM-protected, cryptographically RFC3161/CMS-valid or legally qualified. All evidence stays pilot `Unverified` and #17/#15/#13 remain OPEN.


## Real two-tenant .NET API ZIP interoperability smoke (#167 / ADR 0125)

The standalone offline v1 checker has independent stdlib tests, but those fixtures are produced by Python. The real Keycloak/PostgreSQL two-tenant CI smoke `tests/integration/api-tenant-isolation.py` previously downloaded actual .NET API ZIP bytes yet validated them with generic Python `zipfile` alone; the generic reader can tolerate formats outside TemporalMark's strict v1 profile, so separate producer and verifier tests were **not proof that they interoperate**.

[ADR 0125](../adr/0125-real-api-v1-offline-verifier-ci-bridge.md) / [#167](https://github.com/KeyserDSoze/TemporalMark/issues/167) now invoke the **same** `verify_period_export.verify_archive(io.BytesIO(raw))` on every actual API export **before reading any ZIP member** in disposable signed-Keycloak tenant A, tenant B and forged-header/query trials; count and content isolation checks remain. The bridge logs no raw ZIP, DER, private manifest or bearer; denials are generic and stop smoke CI. Genuine tests-only [GitHub RED 45053967169](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45053967169/attempts/1) showed **one required missing-denial and one positive pass** on a stock-readable ZIP with an opaque internal gap; only after RED did the bridge implementation [`e80fa29`](https://github.com/KeyserDSoze/TemporalMark/commit/e80fa2944177aae5bb5d8a493595363f90253f09) follow. Exact final GREEN must be separately verified.

This adds a **CI interoperability check**, not a production trusted verifier, cryptographic RFC3161/CMS/certificate validation, signed WORM custody, period completeness proof, historical EU QTSP status or eIDAS qualification. Pilot evidence remains `Unverified`; parent #17/#15/#13/#61/#64 remain OPEN.


## Server-side nonblank pilot policy metadata alignment (#181 / ADR 0139)

The standalone v1 ZIP checker already requires `PolicyOid` to be a nonblank string via `bool(value.strip())`. [ADR 0139](../adr/0139-legacy-policy-nonblank-pilot-read-gate.md) now brings the authenticated server-side Page/Search/Receipt/Export **historical** read paths into alignment for empty, ordinary whitespace, tab and Unicode NBSP policy metadata, without rewriting the retained original evidence. Real PG17 and Business tests were committed before source, with independently observed expected [PG17 RED 45202036295](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45202036295) (16 missing denials) and [Business RED 45202193018](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45202193018) (17 missing denials, including search lookahead); source [`1ff8c5f7`](https://github.com/KeyserDSoze/TemporalMark/commit/1ff8c5f74b6a8caddd548671d4485688c34c054c) followed both. Original SHA-consistent DER, canonical SHA256 document imprint, 16KiB nonblank policy, tenant A/B and typed resource limits remain unchanged. This does **not** parse a signed RFC3161/CMS policy identifier, verify an external QTSP, certify a WORM archive, or guarantee that a fully qualified timestamp is authentic. Independently governed RFC3161 service trust #15, evidence custody #17 and CAB/AgID #13 stay OPEN.


## Python `strip` vs .NET source-identifier nonblank parity (#182)

The offline strict v1 checker always required `bool(PolicyOid.strip())` and `bool(ProviderId.strip())`. Python's whitespace set includes U+001C, U+001D, U+001E and U+001F C0 separator controls, whereas .NET `string.IsNullOrWhiteSpace` does not. The same current unqualified pilot source field could formerly be accepted by .NET issuance/direct writer and the server's authorized legacy reads but **fail offline ZIP verification**. [ADR 0140](../adr/0140-python-dotnet-pilot-source-nonblank-parity.md) and [#182](https://github.com/KeyserDSoze/TemporalMark/issues/182) align **original** `PolicyOid` and `ProviderId` nonblank checks with the strict checker, without making the checker lenient, changing archive format or trimming original text. The producer is not a validator of ASN.1/CMS signed policy or eIDAS qualification. Source visibility with embedded C0 remains permitted under the limited v1 nonblank rule.

**Observed test-first evidence:** genuine [PG17 RED 45207944794](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45207944794/attempts/1): 10 expected missing denials / 338 passing, genuine [Business RED 45208375361](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45208375361/attempts/1): 12 expected missing denials / 370 passing; **two new Python checker regressions PASS** in test-only RED, total **36/36**. Only afterward minimal [source `bbc60c06`](https://github.com/KeyserDSoze/TemporalMark/commit/bbc60c06b5422f5143148ed70446638499e104d1) applied on `main`. A ZIP that passes these checks is local structure/hash/metadata consistent only—not signed custody, complete period, QTSP trusted-list or qualified timestamp proof.


## v1 manifest chronology and physical member binding (#183 / ADR 0141)

A generic ZIP may contain a complete set of valid original TSR members and a matching unsigned manifest but in an arbitrary order. The current .NET `temporalmark-period-export-v1` producer writes receipts in the real PostgreSQL `ORDER BY issued_utc, id` order, with `manifest.json` as the **first** physical ZIP local member followed by each receipt in exactly manifest order. Before [ADR 0141](../adr/0141-canonical-order-pilot-v1-export.md), the offline checker verified individual UTC timestamps, UUID uniqueness, paths, local/central ZIP contiguity and DER SHA-256 but accepted **reordered manifest entries or physical TSR members**, including an intact archive with its manifest physically positioned after a TSR. Those archives are not the deterministic layout that this producer actually writes.

The strict unqualified **v1** verifier now requires the manifest `entries` to be **strictly increasing** by `(IssuedUtc` parsed at the existing precise **100ns UTC tick**, canonical UUID numeric order`)`; when timestamps match, the lower RFC UUID sorts first. Physical member order is the exact list `manifest.json` followed by the `responseFile` values in manifest order, using the already pre-validated physical local-header offsets. This is enforced **without extracting** ZIP members or adding an unbounded allocation/decompression; the existing 10,000 receipt, 1MiB/64MiB DER, 8MiB manifest and 80MiB ZIP ceilings and cryptographic self-consistency checks are retained. No reordering of received source bytes is performed. A mismatch is a fixed generic local verification failure and the CLI does not echo tenant, filename, imprint, document or DER.

**Real TDD evidence:** accepted [ADR 0141](../adr/0141-canonical-order-pilot-v1-export.md) FIRST, .NET Business [test-only RED 45213625388](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45213625388/attempts/1) **2 genuinely missing export denials / 383 PASS**, independent Python checker [test-only RED 45214033663](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45214033663/attempts/1) **5 genuinely missing manifest/physical denial checks / 37 PASS**; only then [source `fd4011ee`](https://github.com/KeyserDSoze/TemporalMark/commit/fd4011ee289af3bc8dd2387a90752f434bd89d39). The acceptance includes zero/one/chronologically sorted multi-receipt positive cases and a disposable real PG17 reversed-insertion/SQL-ordered export regression. A locally consistent **unsigned** ZIP is NOT a complete-period attestation, signed custody, WORM legal archive, RFC3161/CMS signature proof, historically qualified QTSP or eIDAS certification. Those remain #17/#15/#13.


## Original UTF8 registry metadata admission budgets (#184 / ADR 0142)

The bounded current **unqualified pilot v1** ZIP exporter already refuses a tenant-owned source registry row if one of its mandatory original text fields (`HashAlgorithmOid`, `DigestBase64`, `PolicyOid`, `ProviderId`) exceeds **16,384 UTF8 bytes** or if the **aggregate original UTF8 bytes of all four fields across all exported rows** exceeds **2,097,152 bytes**. Those caps are separate from the **8 MiB actual serialized JSON manifest**, **80 MiB outer ZIP**, **1 MiB per TSR/64 MiB total DER**, and **8 MiB raw evidence-reference** budgets. Previously the standalone verifier checked the JSON and ZIP size and canonical algorithm/imprint/nonblank source metadata, but accepted a perfectly self-consistent unsigned archive containing e.g. a 16,385-byte `PolicyOid` or 128 individually 16KiB policy entries (>2MiB aggregate), which the current server cannot export.

[ADR 0142](../adr/0142-offline-v1-original-metadata-utf8-budget-parity.md) accepted before [test-only `7e5e13bc`](https://github.com/KeyserDSoze/TemporalMark/commit/7e5e13bca0823a27c5d6e16b02946ea9c2646143), genuine [backend Python RED **45218544666**](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45218544666/attempts/1) **6 omitted denials, 43 passes out of 49**. Only afterward [source `3d4ec8ab`](https://github.com/KeyserDSoze/TemporalMark/commit/3d4ec8abf276a8210fd97090474da33f79e298cd) enforces **original decoded text UTF8 octets**, not Python character counts or escaped JSON byte lengths, per row and cumulatively in the existing bounded manifest loop before reading that row's receipt. An exactly 16KiB printable field and an otherwise valid 127-row under-2MiB export remain accepted; a text field with visible content plus an embedded U+001C separator retains its original value. Errors remain generic and do not echo confidential manifest fields or archive paths. This is **not** a signer trust check, RFC3161/CMS validator, authenticated archive, complete-period proof, WORM or CAB/AgID/eIDAS qualification.
