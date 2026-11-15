# ADR 0007 — Separate signed-OIDC operator provisioning and database roles

Status: Accepted for development/pilot (2026-11-15)

Related: ADR 0003/0006, #14, #22, #23, #24.

## Context
A free-form OIDC subject submitted through SQL was not proof of an active, authenticated user. Reusing the migration-owner database login for the API also allowed bypassing tenant constraints and invoking privileged routines. We need auditable operator enrollment without creating an open, public organization-registration endpoint.

## Decision
1. Deliver a standalone .NET 10 operator executable at `src/backend/applications/TemporalMark.Provisioner`; **it is never hosted by the tenant API**, or exposed through the public React PWA. It accepts a name and paths to **two different, owner-readable only access-token files**, not subject IDs, tenant IDs or raw tokens as arguments.
2. Cryptographically verify BOTH JWT access tokens against the **pinned** OIDC issuer/discovery/JWKS, with exact issuer/audience, strict expiration, `iat` not older than 5 minutes, approved signature algorithms and distinct `sub` values. Provisioner token must carry `platform_provisioner`, first-admin token `tenant_admin`, from the same issuer. The operator role comes only from signed claims (`role` for Keycloak, `roles` for Entra). No unverified claim is used as an identity.
3. Only permit issuer HTTP for explicitly opted-in **loopback development**; production requires HTTPS. Any metadata mismatch, missing key, invalid signing key, unexpected issuer/audience, expired token, invalid role or DB error fails closed.
4. The executable creates a random tenant UUID. The dedicated SQL login (separate from normal runtime and migration owner) may **only EXECUTE** `bootstrap_verified_organization`; it cannot SELECT or mutate organizations/memberships. Function performs the transactional bootstrap and inserts a provisioning audit row in the **same transaction**. Store `issuer`, both subjects and SHA-256 digests of the tokens, never original access tokens. Both digest columns are UNIQUE, so the same token proofs cannot enroll a second organization (including concurrent requests).
5. Migration `V004` creates NOLOGIN grant groups `temporalmark_runtime_group` and `temporalmark_provisioner_group`; normal API has registry/audit SELECT/INSERT and membership SELECT, not tenant-creation DML nor bootstrap execution. Development Compose creates dedicated LOGIN roles with demo credentials; **these are development fixtures only**. Production credentials/role ownership must be provisioned from an approved secret manager and must never be source-controlled.
6. Preserve old `bootstrap_organization` only for migration-owner controlled legacy operation, with no grant to either runtime or provisioner role; its use must be audited and phased out prior to legal production. The new function is `SECURITY DEFINER` with a restricted search path, and its `EXECUTE` permission is denied to `PUBLIC`.

## Limits and outstanding controls
- **A signed access token is not proof the account is currently active**. An IdP can revoke a user after token issue. Immediate introspection/revocation, appropriate auth freshness/step-up MFA, verifiable two-person authorization and human approval records remain release blockers (#23); this pilot accepts a token minted within 5 minutes. Refresh-token/session state is not examined.
- The new SQL function records the caller's validated claims, but PostgreSQL itself cannot validate JWT cryptography. Theft/abuse of the provisioner DB login permits arbitrary enrollment: isolate its credentials and execution environment, require change approval, SQL audit and network restriction. No public API uses this credential.
- The first admin must **already exist** in the trusted IdP. After bootstrap, an identity administrator must configure tenant-specific `organization_id` claim mapping; the current JWT admin API supports one tenant per token. No automatic Keycloak/Entra account creation/invite/claim sync, external identity reconciliation, production role management or multi-org selection.
- Per-issuer subject collision: the tool pins one issuer per run, requires both tokens from it and records issuer alongside subject. Membership key does not yet store issuer, so federation with several issuers is a separate design task.
- The provisioning SQL audit row is guarded by trigger only; **not immutable WORM, signed evidence or qualified service**. Independent sealing/retention and RLS remain open under #17/#14.
- The CI Keycloak realm includes a development-only password-grant client and test users. It must **never** be reused for deployment beyond local/CI. Production token acquisition must use interactive OIDC with PKCE/device authentication and protected operational approval. CLI files must be erased after use.
- Azure/on-prem production do not yet supply automated separate DB credentials/migrations or complete operator workflows (#18/#19). Launch security review remains mandatory.

## Authoritative technical references
- OIDC metadata and issuer checks: https://openid.net/specs/openid-connect-discovery-1_0.html
- IdentityModel JWT result-validation contract: https://learn.microsoft.com/dotnet/api/microsoft.identitymodel.jsonwebtokens.jsonwebtokenhandler.validatetokenasync
- PostgreSQL SECURITY DEFINER threat model: https://www.postgresql.org/docs/17/perm-functions.html
- PostgreSQL GRANT/roles: https://www.postgresql.org/docs/17/sql-grant.html
