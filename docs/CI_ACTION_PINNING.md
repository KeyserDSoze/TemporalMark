# GitHub Actions supply-chain source pinning — #74

**Scope:** stable CI action source references only; no independent security certification. This child of open issue #20 is governed by ADR 0043. The project still requires an actual CAB-reviewed release attestation and approved timestamping controls.

## SHA provenance and rationale

On 2026-11-16, official GitHub Git refs for the major-version tags of the five external actions resolved to these commits. The workflow uses the full commit IDs rather than the movable tags:

| External action | Observed tag | Commit SHA |
| --- | --- | --- |
| actions/checkout | v4 | 11d5960a326750d5838078e36cf38b85af677262 |
| actions/setup-node | v4 | 49933ea5288caeca8642d1e84afbd3f7d6820020 |
| actions/setup-dotnet | v4 | 67a3573c9a986a3f9c594539f4ab511d57bb3ce9 |
| actions/upload-artifact | v4 | ea165f8d65b6e75b540449e92b4886f43607fa02 |
| hashicorp/setup-terraform | v3 | b9cd54a3c349d3f38e8881555d616ced269862dd |

Ten occurrences across backend, frontend, Docker smoke, and Terraform jobs are pinned. Inline version comments are documentation, not selectors. GitHub major-version tags can change without changing this repository. Every future bump must be independently reviewed against the upstream release changelog and exact commit, checked for security advisories, updated using a new literal SHA, and validated on all four jobs at the exact final main SHA. Dependabot suggestions for github-actions may propose upgrades, but may not bypass these review gates.

## TDD and enforcement

ADR 0043 preceded the RED test. The Python standard-library script at tests/integration/check_ci_action_pins.py scans ALL YAML workflow files in .github/workflows; the companion test_check_ci_action_pins.py tests full-SHA references, quoted values and comments, floating tags, branch refs, short/uppercase hashes, dynamic expressions, unpinned docker references, traversal in local action paths, and multiple workflows. Its policy accepts only literal 40-character lowercase SHA references to external actions, or constrained local action paths under .github/actions without traversal. The backend job runs Python unit tests and this real checkout-source policy immediately after checkout.

The initial test caught a local path traversal policy bug and a leading-relative-path handling bug; both were corrected as forward commits before the expected source-policy RED. [CI RED 43857785628](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43857785628) on commit 6df7657 showed three unit tests passed and the workflow source scan failed, naming all ten existing floating action references. GREEN commit 354ea83 replaces them with pinned full SHAs. Complete four-job CI must be verified on the final docs-inclusive main SHA before closing only issue #74.

## Limitations, operations and production gates

This is intentionally a line-oriented source policy, NOT a general YAML interpreter or attestation of all execution. Actions may fetch further mutable code; build steps now use npm ci with checked-in v3 lockfiles following child #75 (see NPM_LOCKED_INSTALLS.md), but still use digest-pinned Node and Nginx test images (ADR 0045 / docs/CI_DOCKER_IMAGE_DIGESTS.md), but still-unverified registry publisher signatures and runner/toolchain provenance, time-varying GitHub runners and other dynamic dependencies. It does NOT deliver SBOM/SAST/secret scans, signed release artifact attestations, GitHub environment protections, reviewed mobile PWA installation behavior, or authenticated cross-tenant API tests. Parent #20 stays OPEN. No FIDO root or independently governed high-water authority is created, so #64/#61/#57 and all WebAuthn enrollment blockers stay OPEN, and V015/V016 registrar SQL issuance remains suspended.

Links: [ADR 0043](../adr/0043-sha-pinned-github-actions-enforced-ci.md), [issue #74](https://github.com/KeyserDSoze/TemporalMark/issues/74), [GitHub Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions), [Git refs API](https://docs.github.com/en/rest/git/refs).
