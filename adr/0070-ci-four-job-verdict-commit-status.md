# ADR 0070 — Publish a fail-closed per-commit four-core-job GitHub CI verdict

Status: Accepted for **development CI visibility only**, 2026-11-18. Focus [#101](https://github.com/KeyserDSoze/TemporalMark/issues/101), child of open CI/reproducibility #20. No production attestation or trust certification.

## Reviewed baseline and evidence gap

Reviewed ADR 0001 and ADR 0043/0050, the complete `.github/workflows/ci.yml`, pinned action policy and Node24 upstream SHA allowlist, Python source unit tests, `docs/CI_ACTION_PINNING.md`, `docs/CI_NODE24_ACTION_RUNTIMES.md`, `docs/ROADMAP.md`, `docs/THREAT_MODEL.md`. Existing four core GitHub Actions jobs are `backend`, `frontend`, `docker-smoke`, `terraform`; `docker-smoke` explicitly requires backend/frontend and can be skipped on their failure. All four must be successful to claim that exact SHA passed.

The connected GitHub integration's `fetch_commit_workflow_runs` exposes no **push-triggered** workflow runs for the recent SHA, and `get_commit_combined_status` reports `statuses: []`. This prevents an independent user-visible query of exact-head 4/4 completion for pending #97–#100. Absence of status is **UNKNOWN**, never GREEN.

Official [GitHub `needs` context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#needs-context) exposes the direct dependencies' exact `result` values `success/failure/cancelled/skipped`. [Job dependency semantics](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-jobs) explicitly support `if: always()` when dependent jobs fail or skip. The [commit statuses REST API](https://docs.github.com/en/rest/commits/statuses) accepts `success` or `failure` on an exact SHA using repository **statuses: write** permission. Statuses are mutable for whoever can write them; they are useful **workflow results** but not a third-party signed, independent CAB attestation.

## Decision

1. Retain the four existing core CI job IDs and unchanged test/security semantics. Add a **fifth job called `ci-verdict`** with direct `needs: [backend, frontend, docker-smoke, terraform]` and `if: ${{ always() && github.ref == 'refs/heads/main' }}`. This job is a reporter, **not** a fifth test or replacement for the actual four. It runs on the main workflow for push/explicit workflow_dispatch, even if one dependency fails/skips. If a workflow is cancelled before reporting, no new status is published; absence stays UNKNOWN.
2. Retain the workflow-wide `permissions: contents: read`. Only the `ci-verdict` job gets explicit `permissions: contents: read` and `statuses: write`. No `issues: write`, PR write, deployments, PAT, secrets besides scoped `GITHUB_TOKEN`, or new external action. Use only the already independently reviewed SHA-pinned `actions/checkout` to load a small standard-library Python script.
3. The reporter reads the JSON `toJSON(needs)` in a job environment variable and accepts exactly the four named dependencies. Report `success` **only if every required direct `result` equals the literal `success`**. Missing, skipped, cancelled, failure, unexpected values, unexpected job sets or malformed payload all become a failure verdict; no exceptions or fallback default to success. Require canonical 40-lowercase-hex `GITHUB_SHA`, safe `GITHUB_REPOSITORY`, positive decimal `GITHUB_RUN_ID` and attempt, and constrain execution to `refs/heads/main`. Reject missing token rather than attempting an unauthenticated write.
4. Post a status directly on that exact `GITHUB_SHA`: context `temporalmark/ci-4-core-jobs`, `state: success/failure`, generic <=140-character description with the four sanitized job results, and `target_url` pointing to the exact original Actions run **and attempt**. Never log the token or arbitrary job output/errors, print signed secrets, or interpolate untrusted fields into a URL. If publication fails, the reporter job fails and **no successful status** can be asserted.
5. **TDD order**: this ADR first; RED-first dependency-free Python unit tests for positive/negative aggregation, bad environment values and source job/permission invariants; add mandatory tests to existing backend; implement minimal reporter, workflow job and operator guide/roadmap/threat notes. A runner-reported status for the **exact current final documentation-inclusive main HEAD** is a necessary verification gate to close #101 or outstanding #97–#100, but still demand linked individual run/jobs and actual test evidence whenever retrievable.

## Limits, safety and rollback

This is **not** a cryptographically signed release attestation, independent monotonic witness, reproducible binary provenance, compromised-runner protection, branch protection, legal/compliance approval or proof of qualified timestamp trust. A status can be overwritten by another authorized actor, and a reporter may fail independently or not run on cancellation. Match the exact `sha`, job status context and run attempt; do not infer past HEAD health. Core jobs and SQL V015/V016/WebAuthn security interlocks are unchanged. Parent #20, qualified QTSP #15, WORM #17 and legal #13 stay OPEN.

## Sources

- [GitHub Actions needs/job results](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#needs-context)
- [GitHub Actions job dependencies and always()](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-jobs)
- [REST commit status create](https://docs.github.com/en/rest/commits/statuses)
