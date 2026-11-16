# ADR 0050 — Explicit native Node 24 GitHub Actions with upstream-verified immutable SHA allowlist

Status: **accepted for CI action-runtime supply-chain provenance, not release certification**, 2026-11-16. Child [#81](https://github.com/KeyserDSoze/TemporalMark/issues/81) of open #20, after completed #74/#75/#76/#77/#78/#79/#80.

## Reviewed context and authority

Reviewed ADR 0001, 0043–0049, `.github/workflows/ci.yml`, `tests/integration/check_ci_action_pins.py` and fixtures, `docs/CI_ACTION_PINNING.md`, `docs/ROADMAP.md`, `docs/THREAT_MODEL.md`, and exact-head successful [four-job CI 43885569528](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43885569528). The runner reports that several SHA-pinned source revisions declare **Node 20**, now deprecated, and the runner **forces Node 24**. This masks a runtime dependency upgrade from the repository SHA even though the action's source reference is immutable. That Node runtime is **not** the PWA's `setup-node.node-version: "22"` CLI runtime.

Queried upstream public GitHub REST `GET /repos/{owner}/{repo}/git/ref/tags/{tag}` and separately inspected exact-SHA raw `action.yml` `runs.using`, **not just floating documentation aliases**, on 2026-11-16:

| Action | Existing immutable SHA (declares node20) | Upstream-verified tag -> new immutable SHA (declares node24) |
| --- | --- | --- |
| `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | `v5` -> `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09` |
| `actions/setup-node` | `49933ea5288caeca8642d1e84afbd3f7d6820020` | `v5` -> `a0853c24544627f65ddf259abe73b1d18a591444` |
| `actions/setup-dotnet` | `67a3573c9a986a3f9c594539f4ab511d57bb3ce9` | `v5` -> `26b0ec14cb23fa6904739307f278c14f94c95bf1` |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` | `v6` -> `b7c566a772e6b6bfb58ed0dc250532a479d7789f` |
| `hashicorp/setup-terraform` | `b9cd54a3c349d3f38e8881555d616ced269862dd` | `v4` -> `dfe3c3f87815947d99a8997f908cb6525fc44e9e` |

**Important variant:** `actions/upload-artifact` `v5` **still declares `node20`** at the upstream v5 tag. It is not an acceptable replacement. The chosen v6 exact-SHA metadata declares `node24`.

Upstream source and changelogs: [GitHub git refs](https://docs.github.com/en/rest/git/refs), [action metadata runs.using](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax), [GitHub Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions), [checkout releases](https://github.com/actions/checkout/releases), [setup-node releases](https://github.com/actions/setup-node/releases), [setup-dotnet releases](https://github.com/actions/setup-dotnet/releases), [upload-artifact releases](https://github.com/actions/upload-artifact/releases), [setup-terraform releases](https://github.com/hashicorp/setup-terraform/releases).

## Decision and required test-first sequence

1. Preserve ADR 0043's existing **generic full 40-character lowercase-SHA pin policy**, and add an **independent offline source-level runtime-allowlist guard** scoped to the five reviewed action repositories and the five exact approved Node 24 SHAs above. This guard is anchored to reviewed upstream `action.yml`, not invented runtime inference. It scans **all** `.github/workflows/*.yml|*.yaml`, rejects any unreviewed SHA, unexpected external action, old deprecated Node20 SHA, and absence of reviewed action families; safe local actions stay covered by ADR 0043's existing guard. Test fixtures show legitimate new exact pins, old known Node20 pins, unknown full SHAs, mutable refs, and multiple workflows. Fail closed when policy provenance changes; future upgrades require another verified official tag+exact metadata review.
2. **RED:** commit ADR before tests; add new Python stdlib policy + offline unit tests to backend source checks **before** existing actions are replaced. Confirm real backend CI fails specifically on old Node20 action revisions, while policy unit fixtures pass and existing generic immutable-ref checks stay green. Source policy cannot introspect remote code on CI; claiming runtime security for arbitrary SHA is prohibited.
3. **GREEN:** replace all twelve action `uses:` references in four jobs with exact new SHAs, retain their documented upstream major tag in comments; retain `permissions: contents: read`, `setup-node.node-version: "22"`, `setup-dotnet.dotnet-version: 10.0.x`, locked npm/NuGet builds, pinned CI containers, SBOM uploads, PostgreSQL witness restore, browser TOTP/PKCE and PWA mobile regression. Do not alter SQL V015/V016 registrar release interlocks or any production tenant/identity/evidence code.
4. Verify on exact final `main` SHA that **all four** jobs succeed; specifically review final runner logs for **absence of forced Node20-to-Node24 warnings**, the new runtime source gate, preserved browser, migration, PostgreSQL full-dump witness and Keycloak MFA jobs. Close **only #81** when verified and document evidence. Keep #20 and release blockers #64/#61/#57/#50/#44/#38/#17/#13 open.

## Residual risk

A reviewed SHA and declared Node 24 runtime are **source and execution selection constraints**, not a signature of the upstream publisher, SLSA/SBOM for arbitrary action dependencies, fixed GitHub runner image or proof that all action internal downloads are immutable. A legitimate Node24 action may still have malicious transitive code, vulnerabilities, a compromised dependency or network requests. GitHub runner images, .NET SDK 10.0.x, CLI Node 22, Playwright browser downloads, Terraform provider drift, permissions/repo policy and deployment secrets require further protection under #20. This work does not confer legal QTSP/eIDAS status, long-term WORM, authentic FIDO MDS trust, or human reviewer authorization.
