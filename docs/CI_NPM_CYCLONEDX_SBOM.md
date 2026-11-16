# CI npm lockfile CycloneDX 1.5 inventories — #77

**Scope: inventory of locked npm dependencies for two source projects.** NOT installed-runtime or container/.NET complete SBOM, vulnerability assessment, signed provenance, legally retained evidence or eIDAS/QTSP certification. [ADR 0046](../adr/0046-ci-npm-lockfile-cyclonedx-inventory.md), scoped [issue #77](https://github.com/KeyserDSoze/TemporalMark/issues/77) under still-open #20.

## Inputs and exported artifacts

`tests/integration/generate_npm_sbom.py` uses **only Python 3 standard library** and committed npm 10 `package-lock.json` files. It does not query registries or execute package code. It strictly validates root metadata and v3 lock source, retains every individual nested package occurrence by unique lockfile-path `bom-ref`, encodes scoped names in `pkg:npm` purls, decodes canonical npm SRI digest bytes to CycloneDX hash hex, and represents the original `dev` and `optional` flags. The root application metadata carries the **SHA-256 of the exact lockfile bytes** and `npm-lockfile-only`/path provenance. No timestamp, invented serial number, dependency edge or signature is asserted. The deterministic file inventory covers **474 PWA** package entries and **8 Playwright** entries, excluding the two lockfile root objects (475 and 9 total each respectively). Entries include OS-specific optional packages that may not be installed at runtime.

The frontend job generates and verifies both JSON inventories **after both npm ci installs and Playwright smoke**, then uploads only `pwa-lockfile.cdx.json` and `playwright-lockfile.cdx.json` as the single artifact `npm-lockfile-cyclonedx` with `retention-days: 7`. Uploading empty files fails the job; it uses the already SHA-pinned `actions/upload-artifact`. GitHub Actions still uses `permissions: contents: read` without identity-token or write additions. The short-lived artifact is downloadable from the corresponding CI run by users with appropriate repository access; it is **not signed or immutable** and is not a substitute for a retention system.

## TDD and verification evidence

1. ADR 0046 committed before tests as `f12fba9`. The test-first source guard and 5 offline policy regressions were committed at `b3e4623`.
2. **Real RED** [Actions 43873432766](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43873432766): **5/5 policy tests passed**, then the backend source gate failed specifically on missing frontend SBOM generation, verification, SHA-pinned upload, JSON path and retention. Existing backend security policies passed.
3. GREEN candidate [`9d30732`](https://github.com/KeyserDSoze/TemporalMark/commit/9d3073252dc0c35c58eaf6ffa2ddebf3eb6a4bc6) added deterministic generator, semantic comparison against each source lockfile and adversarial tests, and enabled the frontend generation/verification/upload steps. [Run 43874005747](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43874005747) successfully produced **474+8 package inventories**, verified both, and uploaded artifact ID **14229311574** (49 KB compressed; expires 2026-11-23).
4. Candidate [`f56affd`](https://github.com/KeyserDSoze/TemporalMark/commit/f56affdff13dcbbe07d75509680a1edff8a2a27e) also runs **7 adversarial semantic inventory unit tests** in backend CI: exact lock coverage, deterministic output, purl scope/nested duplicates, missing/injected components, wrong/ref duplicate/hash version, lock tampering/source changes, invalid SRI and corrupted JSON roundtrip. Frontend creates then re-reads and verifies its files before uploading.
5. For final completion, **all four GitHub Actions jobs must be SUCCESS on the exact final `main` SHA** and real PostgreSQL full logical `pg_dump/pg_restore`, Keycloak MFA/PKCE, PWA safety and Terraform remain green. Put the final run and SHA in [issue #77](https://github.com/KeyserDSoze/TemporalMark/issues/77); close **only** this child after observed success.

Reproduce locally from the repository root (Python 3):

```sh
python3 tests/integration/generate_npm_sbom.py generate --output-dir /tmp/temporalmark-npm-sbom
python3 tests/integration/generate_npm_sbom.py verify --output-dir /tmp/temporalmark-npm-sbom
python3 -m unittest discover -s tests/integration -p 'test_generate_npm_sbom.py' -v
```

**Limits:** Output describes *requested/locked* npm tarballs, not installed binaries, platform-specific optional outcomes, Keycloak, PostgreSQL, Node, .NET/NuGet, Docker images, frontend asset bytes, Playwright-managed Chromium, license provenance, vulnerabilities, or complete dependency edges. The converter's strict canonical comparison detects tampering **relative to the checked-in lockfile**, not malicious/corrupted source before commit, a compromised runner or untrusted publisher. It is not a third-party certification that every possible CycloneDX schema interpretation passes. A short retention CI artifact is neither SLSA provenance nor CAB-accepted cryptographic attestation or WORM. Parent #20 remains OPEN for whole-system SBOM, SCA/SAST/secret scan, image signatures, evidence retention and release attestations. Witness/FIDO/security #64/#61/#57/#17 and registrar V015/V016 freeze unchanged.

References: [CycloneDX JSON 1.5 schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.5.schema.json), [GitHub Actions artifacts](https://docs.github.com/en/actions/using-workflows/storing-workflow-data-as-artifacts).
