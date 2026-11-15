# ADR 0005 — Pilot tenant audit of evidence access

Status: Accepted (2026-11-15)

## Context
ADR 0003 requires audit of tenant-sensitive actions. Neither application logs nor the PostgreSQL registry are independently immutable evidence.

## Decision
Introduce a tenant-scoped, append-only (at the application/schema level) event table. Each event carries organization ID from a validated JWT + membership DB lookup, the OIDC subject, UTC timestamp and an action-specific, bounded metadata payload.

Supported events in this slice:
- `period_export_prepared`: a ZIP has been prepared and its audit row persisted **before** returning bytes; store the half-open UTC interval, not source file content or digest.
- `receipt_download_prepared`: an existing tenant-specific receipt has been found; persist its ID **before** returning DER bytes.

`Prepared` explicitly **does not mean delivered**: network disconnections after the audit entry are possible. If audit persistence fails, the endpoint fails closed and returns no evidence body. The audit listing uses the same server-resolved, DB-verified tenant admin as the registry and limits each response to at most 200 rows.

## Constraints and consequences
- The event table is not WORM, signed, hash chained or legally tamper-proof. Database owners can bypass triggers.
- No issuance event yet; recording timestamp creation atomically with token persistence and sealing is a separate prerequisite for production. See #15/#17.
- Production must add independent signing/anchoring, qualified storage and retention/privacy policy, tested RLS, controlled migrations and separate database roles.
- A download response may still fail after an audit row is inserted; design event semantics accordingly.
- Events record the `sub` claim only, never raw JWTs, secrets, source documents or TSR bytes.

Related: issue #21, ADRs 0003–0004.
