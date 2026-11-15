# ADR 0014 — Reviewer-only original enrollment scope (pilot)

Status: Accepted for pilot, 2026-11-15. Related #35/#36/#31/#27, ADR 0009–0013.

## Context

The old restricted CLI passed reviewer-confirmed organization name and operator/initial-admin OIDC subjects as command-line arguments. The database verified their equality to the pending enrollment, but a human reviewer could be shown only *operator-supplied values* instead of the original pending record.

## Decision

1. Versioned PostgreSQL **V009** adds SECURITY DEFINER `public.read_pending_enrollment(uuid,text,text)`. Its EXECUTE privilege is granted **only** to `temporalmark_approver_group`; `PUBLIC`, provisioner and runtime roles cannot use it, and no direct `organization_enrollment_requests` SELECT is granted. The function exposes exactly one original pending ID, legal name, issuer, operator subject, first-admin subject and UTC expiry (no token hashes, memberships or global listing), only while unapproved, unconsumed and unexpired, with reviewer != operator/admin.
2. The separate standalone `review --request-id UUID --approver-token-file PATH` CLI checks a cryptographically signed and fresh OIDC reviewer role, pinned issuer/ACR, live RFC7662 token state and current Keycloak realm role *before* calling the SQL routine. It prints **the original database state**, not repeated argv fields, along with a canonical SHA-256.
3. The SHA-256 is domain-separated and computed over UTF-8 **length-prefixed** exact fields: request ID, original name, issuer, operator/first-admin subjects and expiry UTC ticks. The CLI `approve --request-id UUID --review-sha256 HEX --approver-token-file PATH` no longer accepts caller-supplied name or subject fields. The business service refreshes the original record, checks the supplied digest in constant time, and passes only database-returned fields to the existing SQL approval routine, which rechecks all scope and expiry. A wrong digest or expired/consumed request cannot be approved through this CLI.
4. CI covers business canonical field mutation, wrong-digest denial, already-approved read denial, SQL privilege isolation, and real Keycloak protected-token reviewer workflow. Applied migrations V001–V008 are not modified.

## Trust boundary and limits

**A digest is NOT an approver's signature, FIDO2 assertion, independent-human review certificate or legal evidence.** A compromised reviewer bearer+DB credential can still approve, and the *existing* 10-argument SQL approval function remains callable by the restricted reviewer DB role for compatibility without a signed review receipt. The new CLI adds an explicit confirmation step, **not DB-level cryptographic binding**. #35 remains OPEN to implement authentic independently witnessed accept/reject with reviewer-held challenge signing, DB-side atomic policy binding, external governance and signed/WORM audit. The demo password-grant fixture is NON_MFA, and the separate OTP/PKCE CI realm (#34) is not production enrollment. This is not QTSP qualification (#13).

Sensitive legal names and account subjects are printed only to the authenticated reviewer's controlled console. Use the independent approved legal-entity directory for reconciliation; never place JWTs/OTP seeds in argv, audit text or CI artifacts.

References: PostgreSQL function/privilege docs https://www.postgresql.org/docs/17/sql-createfunction.html and https://www.postgresql.org/docs/17/sql-grant.html ; OIDC https://openid.net/specs/openid-connect-core-1_0.html.
