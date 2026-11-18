# GitHub commit status: exact four-job CI verdict (#101)

**Scope: development workflow observability, not a signed reproducible-build
attestation or qualification dossier.** This feature closes an observability gap
in the GitHub integration: direct retrieval of push-triggered Actions runs is
sometimes unavailable even when the `CI` workflow executes.

## Behavior

The existing `.github/workflows/ci.yml` still runs the original four checks
without any weakening:

- `backend`: source controls, locked NuGet, .NET 10 tests and publish, V015 guard, SBOM;
- `frontend`: locked npm, PWA build/Playwright/mobile, SBOM;
- `docker-smoke`: real PostgreSQL/Keycloak MFA and signed multi-tenant API/PWA integration;
- `terraform`: formatting, initialization and validate.

After *all four*, a **fifth reporting-only** `ci-verdict` job runs on `main`
with `needs: [backend, frontend, docker-smoke, terraform]` and `if: always()`.
Its job-scoped token permissions are `contents: read`, `statuses: write`.
The four existing jobs keep the workflow-wide `contents: read` token.
The publisher pins `actions/checkout` to the pre-reviewed full commit SHA,
sets `persist-credentials: false`, runs Python standard library only and
never receives a PAT, issue/PR-write privilege or external service secret.

`tests/integration/publish_ci_verdict.py` reads the **GitHub-supplied**
`toJSON(needs)` result from the same workflow. It posts a GitHub commit status
under the fixed context:

```
temporalmark/ci-4-core-jobs
```

with an exact 40-character `GITHUB_SHA`, a short sanitized result per core
job, and a link to the original Actions run/attempt. All four must report
exact literal `success`; **a failed, cancelled, skipped, missing, malformed
or unexpected result is failure**. The publisher refuses off-main SHA/ref,
malformed run identity or missing token. It never reads logs or prints raw
job contents or bearer tokens.

## Check before closing a GitHub issue

1. Read the **actual current `main` SHA**; do not reuse an old result or
   assume the source change already passed.
2. Read its GitHub commit combined statuses and select the literal context
   `temporalmark/ci-4-core-jobs`. Confirm `state=success` **on that exact
   SHA**, with a run URL to the exact workflow attempt. The combined status
   may also contain unrelated statuses; check the specific context.
3. Inspect the linked Actions run/jobs and actual relevant tests when
   available. Record the SHA, run ID/attempt, four success job names and any
   meaningful test counts as verifiable evidence. **Do not fabricate counts
   or label synthetic fixtures as QTSP integration tests.**
4. Close only the issues whose own acceptance requirements are fulfilled.
   Never close parent #20/#15, WORM #17 or legal #13 just because CI passes.

A missing/pending status is **UNKNOWN**, not success. A failure status means
at least one primary job did not finish successfully; use its exact Actions run
to diagnose. If GitHub cancels the workflow before the reporter executes, or
the reporter lacks the repository permission to create a status, it cannot
produce a success verdict. If it posts failure due to absent dependency data,
that is the deliberate safe outcome. Review unexpected status updates, branch
protection and write permissions, since commit statuses are **mutable** and
are NOT independently signed. The publisher's own run can also fail after a
core success; absence is still a blocker for issue closure.

## Testing

```sh
python3 -m unittest discover -s tests/integration -p 'test_publish_ci_verdict.py' -v
python3 tests/integration/check_ci_action_pins.py
python3 tests/integration/check_ci_action_runtimes.py
```

The Python tests include all-four-success, every missing/skipped/failed/
cancelled/unrecognized job, invalid SHA/repo/run/attempt/ref, sanitized
descriptions, scoped REST status publication through a mocked HTTPS call,
permission and workflow topology source guards. They run early in the
existing `backend` CI job. A successful local unit test is **not** 4/4 CI.

## TDD and residual security limitations

[ADR 0070](../adr/0070-ci-four-job-verdict-commit-status.md) preceded the
new tests, followed by the Python implementation and fifth reporter job.
This reporter observes only GitHub Actions' **reported job results**.
A compromised workflow/runner/account, mutation of branch protections,
unaudited action supply chain, or rerun on a stale SHA is outside its proof.
Neither an archived legal timestamp nor a QTSP certificate/UTC(k) source
can be inferred from a GitHub commit status. On-prem and Azure application
features, tenant isolation and V015/V016 registrar interlocks are unchanged.

Parent issue [#20](https://github.com/KeyserDSoze/TemporalMark/issues/20),
implementation [#101](https://github.com/KeyserDSoze/TemporalMark/issues/101).
RFC3161 pilot children #97–#100 remain OPEN until exact-head CI is actually
verifiable and their own tests complete. All pilot timestamps stay `Unverified`.

Official sources:
[GitHub job needs results](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#needs-context),
[job dependencies](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-jobs),
[commit status REST](https://docs.github.com/en/rest/commits/statuses).
