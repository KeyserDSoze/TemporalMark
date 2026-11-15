# ADR 0015 — Terminal enrollment rejection and cross-decision replay protection

Status: Accepted for pilot application control, 2026-11-15.
Related: #37 (scoped), #35/#31/#27 (parent), ADR 0009, 0011–0014.

## Context

The previous three-person CLI supported pending request → reviewed approval → completion, but had no explicit **REJECT** transition. Reviewers could decline an enrollment only by letting the five-minute request expire. The older PostgreSQL approval procedures were still executable with the approver SQL login; after adding rejection, those legacy functions must not re-approve a terminally rejected request. Distinct token-proof hashes were already enforced for approvals, but we also need a single-use invariant **across both approval and rejection**.

## Decision

1. Immutable `V010__terminal_enrollment_rejection.sql` adds nullable, transactionally stored `rejected_by_subject`, `rejected_utc`, `rejection_proof_sha256`, `rejection_review_sha256`, and `rejection_reason_code` to the original request. The five fields must be **all absent or all valid**. Valid reasons are exactly `UNVERIFIED_ORGANIZATION`, `UNVERIFIED_IDENTITY`, `SCOPE_MISMATCH`, and `POLICY_DENIED`. There is no freeform reason text or raw JWT, OTP or secret.
2. `public.reject_enrollment(uuid,text,text,text,text,text,char(64),char(64),text)` is a SECURITY DEFINER function with fixed `pg_catalog,pg_temp` search path and fully qualified table. **EXECUTE is granted only to the existing independent approver SQL group.** The function checks UUID, original name, exact issuer, two original subjects and third distinct reviewer, uppercase SHA-256 proof and reviewed digest, expiry, absence of prior approval/rejection/consumption, and an allowlisted reason. A single conditional row UPDATE atomically wins or loses against competing decisions.
3. A CHECK constraint makes approval+rejection mutually exclusive **even when the historical 10-argument SQL approve routine is called after rejection**. `V010` redefines the V009 reviewer-read routine, without editing V009, so rejected requests are immediately excluded from the pending review. The existing completion routine requires an already approved request and cannot consume a rejected one. Operator/runtime SQL roles have neither reject EXECUTE nor table UPDATE.
4. A new `organization_reviewer_decision_proofs` registry has a UNIQUE token SHA-256 across **both** decision types and UNIQUE request UUID. Existing approved token fingerprints are backfilled honestly, without changing their ACR/legacy assurance or marking a past approval as a rejection. An AFTER UPDATE trigger inserts a new proof in the **same SQL transaction** as a new approval or rejection, so a token reused for another approval/rejection causes a unique violation and rolls back the decision.
5. The standalone CLI now supports `reject --request-id ... --review-sha256 ... --reason-code ... --approver-token-file ...` via the approve-only DB credential. `RejectReviewedAsync` validates the mandatory enum-like reason, performs a **new** signed OIDC + policy ACR/freshness + live RFC7662 + current effective Keycloak role check, reads the original pending request and compares the supplied digest in constant time. It repeats live authorization just before invoking the SQL rejection store. Status is recorded only after the SQL transaction succeeds. It never claims the review SHA-256 is a reviewer-held signature.
6. Automated checks: TDD RED→GREEN business authorization/mismatch/reason/replay tests; PostgreSQL role grants, terminal no-tenant invariant, cross-decision token reuse and concurrent approve-versus-reject; real disposable Keycloak signed-token smoke with wrong digest/reason denial, one successful reject, replay denied, and inability to subsequently read, approve or complete the request.

## Security boundaries / deliberately unfinished work

- `rejection_review_sha256` is **a scope digest, not a human signature**. The database SQL routine cross-checks the original scope but cannot itself prove that the reviewer saw it or verify a FIDO2 signature. An attacker with the restricted approver SQL login can call the new reject function directly with a hash. It can also call the older approve routine on a *pending* request; the new terminal DB constraint only prevents approving one *already rejected*.
- IdP directory/authentication and PostgreSQL commit are not a distributed atomic transaction. JWT theft, credential compromise, account/role changes between checks and SQL commit remain risks. The disposable password grant fixture explicitly performs **NO MFA** and must not be deployed outside CI. A separate OTP/PKCE fixture tests the technical LoA2 flow but not independent human/device possession.
- The pilot request table and proof registry are ordinary PostgreSQL under the migration owner's control, **not immutable/WORM**, externally signed evidence or a qualified trust-service record. Production requires reviewer-held challenge signing/explicit human approve-or-reject, trusted attested key enrollment, key rotation, independent governance, and tamper-evident evidence. Keep **#35, #31, #27, #17 and #13 OPEN** until those requirements are delivered and independently reviewed.
- Older migrations V001–V009 remain immutable. The approval request still expires after five minutes; if expired or rejected, operators must submit a new independently verified request rather than retroactively reusing it.

## Primary technical references

- PostgreSQL 17 `SECURITY DEFINER` and safe `search_path`: https://www.postgresql.org/docs/17/sql-createfunction.html
- PostgreSQL 17 row triggers: https://www.postgresql.org/docs/17/sql-createtrigger.html
- RFC 7662 Keycloak live access-token introspection: https://www.rfc-editor.org/rfc/rfc7662

## V011 security hardening (2026-11-15)

A RED owner-level PostgreSQL test showed that a nullable decision-reason or review-digest comparison inside the V010 `CHECK` can evaluate to SQL **UNKNOWN**, which is considered valid for `CHECK` constraints. The restricted SECURITY DEFINER function already validated these inputs, but a direct database-owner update could create an incomplete terminal row. The immutable corrective `V011__rejection_required_metadata.sql` adds explicit `IS NOT NULL` checks for every rejected identity/reviewer proof/scope digest/reason and tests NULL fields are refused with a check violation. No prior migration checksum is modified; this is a database consistency safeguard, **not** tamper-proof audit or legally sealed evidence.
