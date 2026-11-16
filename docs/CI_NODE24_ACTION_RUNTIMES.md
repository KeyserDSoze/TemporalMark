# Native Node 24 GitHub Actions at reviewed immutable SHAs (#81)

Decision: [ADR 0050](../adr/0050-native-node24-sha-pinned-github-actions.md), extending existing source-pinning [ADR 0043](../adr/0043-sha-pinned-github-actions-enforced-ci.md). Scope: **the runtime declared by the five external GitHub Actions**; NOT the CLI Node 22 used by the PWA, nor an independently reproducible GitHub hosted runner.

## Verified upstream provenance (2026-11-16)

These are exact GitHub `git/ref/tags` commit dereferences, independently matched to `action.yml` read from the **same literal SHA**. All five action metadata files explicitly state `runs.using: node24`; the five old pinned SHAs explicitly stated `node20`.

| Action | Upstream tag | Approved SHA | Occurrences |
| --- | --- | --- | --- |
| actions/checkout | v5 | `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09` | 4 |
| actions/setup-node | v5 | `a0853c24544627f65ddf259abe73b1d18a591444` | 2 |
| actions/setup-dotnet | v5 | `26b0ec14cb23fa6904739307f278c14f94c95bf1` | 2 |
| actions/upload-artifact | v6 | `b7c566a772e6b6bfb58ed0dc250532a479d7789f` | 3 |
| hashicorp/setup-terraform | v4 | `dfe3c3f87815947d99a8997f908cb6525fc44e9e` | 1 |

**Do not use** `actions/upload-artifact@v5`: its upstream metadata still declares `node20`. Every SHA above is an immutable commit reference at the time verified, not an automatically updated major tag. Source references retain their major tag only as informational inline comments. Future reviewers must inspect upstream commit, exact `action.yml`, release notes and potential security advisories before changing the allowlist.

## Test-driven implementation and runbook

- **RED:** ADR 0050 committed before the new test. At [CI 43887807050](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43887807050), SHA `ac5311facf91042483c02656ababe0176f021313`, 5/5 Python runtime-policy unit tests PASS, existing immutable-source guard PASS, **mandatory new repository guard FAIL** on precisely twelve deprecated Node20 pinned action references across the four jobs. This failure precedes all further backend tests intentionally.
- **GREEN:** replace the 12 legacy `uses:` SHAs, keep the exact CLI `node-version: "22"`, `dotnet-version: 10.0.x`, `permissions: contents: read`, four job topology, all locked npm/NuGet restore checks, PWA offline/mobile tests, full PostgreSQL witness restore and browser Keycloak TOTP/PKCE tests. The new `check_ci_action_runtimes.py` enforces a **closed** source allowlist of the five reviewed exact 40-hex action SHA IDs and rejects old Node20 refs, any unknown external action or changed SHA in any workflow. The prior generic `check_ci_action_pins.py` remains independent.
- Verify source offline with `python3 -m unittest discover -s tests/integration -p 'test_check_ci_action_runtimes.py' -v`, `python3 tests/integration/check_ci_action_pins.py` and `python3 tests/integration/check_ci_action_runtimes.py`. CI must verify all four jobs SUCCESS **on the exact final main SHA**, plus **no forced Node20-to-24 runtime warnings in executed job logs**. The job environment itself is only a GitHub hosted service, not WORM or independent custody.

## Constraints and remaining work

An approved commit SHA and `action.yml` declaration do not prove the action's dependencies are benign or pinned, runner image is reproducible, or an executable is publisher-signed. The GitHub runner's Node runtime is not the PWA's build runtime; do not change frontend Node 22 merely to eliminate a warning about Action Node 20. Maintain the supported GitHub runner version required by upstream Node24 action metadata and do not infer safety from a successful job alone.

Parent #20 remains open for locked runner toolchains and signed release/SLSA provenance, vulnerability/SAST/secret scanning, robust cross-tenant data security and actual physical mobile installation. #64/#61/#57/#50/#44/#38/#17/#13 are unchanged. No claim of qualified QTSP status, production WORM, authentic FIDO MDS R46 trust or authorized WebAuthn human consent.

Sources: [GitHub action metadata](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax), [Git ref API](https://docs.github.com/en/rest/git/refs), [GitHub Actions security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions).
