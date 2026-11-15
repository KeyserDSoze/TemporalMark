# ADR 0003 — Tenant isolation and last administrator invariant

Status: Accepted (2026-11-15)

## Decision
A tenant represents a legal customer organization, not a cryptographic TSU. A user may belong to multiple organizations, with independently assigned roles. All persisted business records have a non-null tenant ID. Every query and export MUST apply server-derived tenant authorization; NEVER trust an arbitrary tenant ID from the request path/body. Prefer `organization_id` in verified OIDC claims paired with a validated membership lookup. System operators must not automatically see tenant contents.

Tenant roles: `tenant_admin`, `tenant_auditor`, `tenant_member`. Every active organization must have at least one active tenant administrator. Bootstrap of the first admin and membership deletion/role changes must be transactional and concurrency safe. Privileged platform roles require explicit break-glass access and independent audit trails. All administration and export actions require an immutable audit event.

Use database constraints and (later) PostgreSQL RLS as defence in depth; never rely on UI filtering for isolation. Storage keys are prefixed/partitioned by tenant; tenant identity may not be overwritten on an existing timestamp.

## Open work
User/organization enrollment, external IdP claim mapping, transactional last-admin enforcement, cross-tenant automated authorization testing, DB RLS and audit event tamper evidence are release blockers, not optional enhancements.
