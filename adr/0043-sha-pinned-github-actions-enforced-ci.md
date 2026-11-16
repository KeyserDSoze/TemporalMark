# ADR 0043 — SHA-pin external CI actions and enforce source policy

Status: **accepted for CI supply-chain hardening, not production assurance**, 2026-11-16. [#74](https://github.com/KeyserDSoze/TemporalMark/issues/74), child of open [#20](https://github.com/KeyserDSoze/TemporalMark/issues/20).

Reviewed `adr/0001`, `adr/0040`–`0042`, `docs/ROADMAP.md`, `docs/THREAT_MODEL.md`, `docs/PWA_SERVICE_WORKER_SECURITY.md`, the complete `.github/workflows/ci.yml` and `.github/dependabot.yml`. Current job names and on-prem/Azure test parity remain unchanged. A reproducible CI action **source** is a necessary input to the trust evidence dossier; it is not equivalent to authentic FIDO MDS R46, a separately governed witness, legal timestamp qualification, or fully reproducible builds.

## Problem

Workflow jobs currently resolve floating aliases such as `actions/checkout@v4`. Version aliases are maintained by external action publishers and may point to different commits later, while the TemporalMark commit remains unchanged. A replay of the same `main` SHA may execute a different action implementation. This risk affects the real two-cluster witness full-restore tests, MFA and release evidence. `npm install`, `node:22-alpine`, `nginx:1.27-alpine`, Terraform providers, unpinned GitHub runner images and downloads remain further independent drift sources under #20.

## Decision

1. Verify the Git object behind official action major-version tags using public GitHub REST `GET /repos/{owner}/{repo}/git/ref/tags/{tag}` before hard-coding the actual 40-character commit SHA. On 2026-11-16 the retrieved targets were:

   | Action | Resolved official tag | Commit SHA |
   | --- | --- | --- |
   | actions/checkout | v4 | `11d5960a326750d5838078e36cf38b85af677262` |
   | actions/setup-node | v4 | `49933ea5288caeca8642d1e84afbd3f7d6820020` |
   | actions/setup-dotnet | v4 | `67a3573c9a986a3f9c594539f4ab511d57bb3ce9` |
   | actions/upload-artifact | v4 | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
   | hashicorp/setup-terraform | v3 | `b9cd54a3c349d3f38e8881555d616ced269862dd` |

   Pin every external occurrence, not just `checkout` in the backend job. Inline comments may record the major tag but must **not** control resolution. Future upgrades require explicitly reviewed commit hashes, upstream changelogs and fresh CI/security evidence; Dependabot suggestions must not bypass the policy.

2. Add a dependency-free Python source guard `tests/integration/check_ci_action_pins.py`: enumerate *all* `.github/workflows/*.yml|*.yaml`, reject missing workflows, YAML `uses:` keys with empty/unrecognized syntax, GitHub expressions, short SHA, mutable tags/branches, or unpinned `docker://` refs. Permit local `./.github/actions/...` actions only if no traversal, absolute path or interpolation, and review their local sources separately. The guard is a narrow source policy, **not a full YAML parser** or scanner for commands like `curl | bash`; do not claim otherwise. Unit tests exercise both positive/negative cases and policy matching across workflow files.
3. TDD order: ADR before **RED**. Add guard and backend job enforcement while `uses` aliases remain unchanged, verify a real CI backend failure specifically reports mutable references. Only then **GREEN** replace aliases with the five verified full SHAs. Keep the existing backend, frontend, docker-smoke and terraform jobs and all integration smoke coverage; require all four SUCCESS on *exact final main SHA* before closing only #74.
4. Update docs/ROADMAP and docs/THREAT_MODEL. Explicitly leave lockfiles + `npm ci`, Docker image digests, SBOM/SAST, signed attestations, GitHub runner provenance, production CAB/IdP trust and mobile PWA testing under parent #20. Do not change SQL V015/V016 registrar release interlocks, FIDO trust issues #64/#61/#57, tenant isolation or production Azure/on-prem contracts.

## Remaining risks and operations

A pinned action commit may still contain a vulnerability or malicious logic; a compromised action GitHub repo, dependencies dynamically fetched by that action, local source checkout, build network or mutable toolchain can still attack CI. Use least-privilege workflow `permissions: contents: read`, review pinned action code and upgrades, restrict protected-branch writes, sign/attest artifacts and adopt SCA/SAST/SBOM and lockfiles before a production release. The policy is not an attestation, independently verifiable build receipt or QTSP audit.

Sources: [GitHub Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions), [Git refs API](https://docs.github.com/en/rest/git/refs).
