# CI restored NuGet CycloneDX 1.5 inventory — #78

**Scope: actual CI .NET SDK NuGet restore snapshots for all nine TemporalMark .NET 10 projects.** This is NOT a NuGet lockfile, installed-runtime/container SBOM, package security scan, publisher signature, certified build, CAB-held evidence or qualified timestamping. Governed by [ADR 0047](../adr/0047-ci-nuget-restored-graph-cyclonedx-inventory.md), issue [#78](https://github.com/KeyserDSoze/TemporalMark/issues/78) (child of open #20).

## Input and output contract

The backend GitHub Actions job restores all `*.csproj` under `src/backend` and `tests/backend` (exactly **nine**: five production and four test projects). These commands populate each project's temporary SDK-generated `obj/project.assets.json` in the CI runner. The Python-standard-library `tests/integration/generate_nuget_sbom.py` discovers the nine project files, verifies each assets file/target set, recognizes explicit NuGet schema versions **3 or 4**, and extracts **only** `libraries` with `type: package`. It excludes `type: project` references, which are already represented in the nine projects' scope. Each per-project package occurrence retains:

- Exact NuGet package name, restored version and `pkg:nuget/Name@Version` package URL; a **project-qualified** `bom-ref` is used even if multiple projects restored the same NuGet package/version.
- NuGet package SHA-512 decoded from the actual canonical base64 `library.sha512`, rendered as CycloneDX hexadecimal hash; no fabricated package hash, no material from NuGet credentials or full assets file.
- A source-project property; the application-level metadata records **all nine csproj and project.assets SHA-256 hashes** and the `nuget-restored-graph-only` scope. Hashes reflect the exact ephemeral CI restoration and may vary between runs; they are not trusted provenance signatures.

One deterministic `nuget-restored.cdx.json` document is written to `$RUNNER_TEMP/temporalmark-nuget-sbom`. The verifier rereads the file, compares the *complete* canonical contents against the current nine original source files and refuses extra/missing or duplicated components, wrong PURL/version/hash/source identity, malformed JSON, missing/restored source and unknown future NuGet versions. The backend job runs nine adversarial unit regressions, then actual generation and verification **before** uploading only the JSON under short-lived artifact `nuget-restored-cyclonedx`, SHA-pinned GitHub `actions/upload-artifact`, `retention-days: 7`, `if-no-files-found: error`. No broadened GitHub token permissions: `contents: read` only.

## Test-first evidence and NuGet SDK compatibility

1. ADR 0047 [commit b134702](https://github.com/KeyserDSoze/TemporalMark/commit/b134702cc33cd1b05fb6622dbf873d1ed8eb3416) preceded RED tests. Offline source policy and fixtures were committed in forward-only commits `b6f287d`, `802bcf2` and `3c05b30`.
2. **Real RED** [Actions 43877379110](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43877379110): five source-policy unit regressions PASS, mandatory repository source policy FAIL on missing nine-project restore, generator, semantic verifier and seven-day pinned upload.
3. First GREEN candidate `fddfef0` added the converter, tests and actual workflow steps, but [CI 43878060084](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43878060084) exposed a source-policy fixture ordering mistake (the real shell discovers projects before iterating `dotnet restore`), corrected by forward commit `7f71b2d`. The next [CI 43878487858](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43878487858) then reached the **real** restored SDK files and found `assets.version=4`, which the first strict v3 parser did not support.
4. [NuGet's accepted SDK v4 proposal](https://github.com/NuGet/Home/blob/dev/accepted/2025/Multiple-Equivalent-Framework-Support-TFM-As-Aliases.md) explains version 4 for .NET 10 SDKAnalysisLevel 10.0.300+. Fix `7eb7883` allows **only** version 3 or 4 and explicitly rejects future versions (tests included), without weakening package SHA-512 or source constraints. **NuGet itself warns that assets format is not stable** ([NuGetAudit 2.0](https://devblogs.microsoft.com/dotnet/nugetaudit-2-0-elevating-security-and-trust-in-package-management/)); review future SDK changes rather than assuming schema compatibility.
5. Actual [GREEN CI 43878993393](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43878993393): **9/9** adversarial test cases PASS, actual SDK restorable assets parsed, **185 restored NuGet package occurrences across 9 projects**, generated and independently verified. A real GitHub Actions artifact `nuget-restored-cyclonedx` was uploaded with ID **14231163433** (16,336 bytes, expires November 23, 2026); separate npm SBOM artifact also uploaded. The scope-only test does NOT yet close the issue; final docs-inclusive main SHA must pass all four CI jobs and real database/identity/PWA checks.

## Reproduction

From the repository root with .NET 10 SDK and Python 3:

```sh
find src/backend tests/backend -type f -name '*.csproj' -print0 | sort -z | xargs -0 -n1 dotnet restore
python3 -m unittest discover -s tests/integration -p 'test_generate_nuget_sbom.py' -v
python3 tests/integration/generate_nuget_sbom.py generate --output-dir /tmp/temporalmark-nuget-sbom
python3 tests/integration/generate_nuget_sbom.py verify --output-dir /tmp/temporalmark-nuget-sbom
```

For real evidence always inspect the **exact CI head SHA**, all job results and uploaded artifact retention/size before accepting the scoped child.

## Residual risk / nonclaims

Unlike `package-lock.json`, NuGet `project.assets.json` is **temporary and not source-controlled**: package resolution and the restored package list can differ by SDK, CI runner, available feed, RID, target framework or time. The SHA-512 metadata is not an independently verified publisher signature. The inventory is one JSON file for nine projects, **not** an SBOM for final application bytes, Windows/Linux native libraries, npm assets, container OS packages, Playwright Chromium, PostgreSQL, Keycloak, Terraform, or on-prem/Azure production distribution. No vulnerability matching/SAST/SCA, complete dependency-graph edges, license certification, SLSA signing/attestation, independent WORM witness, CAB-approved key ceremony, FIDO Alliance R46 root trust or eIDAS qualified timestamp assurance. Parent #20 remains OPEN for NuGet locked-mode builds, OCI/runtime SBOM, vulnerability scans/secret scanning, signature verification, signed artifacts, PWA install/mobile and cross-tenant API proof; security #64/#61/#57/#17 and registrar V015/V016 freeze unchanged.

Technical sources: [NuGet dependency resolution](https://learn.microsoft.com/en-us/nuget/concepts/dependency-resolution), [CycloneDX v1.5 JSON schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.5.schema.json).
