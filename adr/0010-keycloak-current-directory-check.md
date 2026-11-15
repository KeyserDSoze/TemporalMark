# ADR 0010 — Current Keycloak directory account/role authorization gate

Status: Accepted for **pilot** (2026-11-15). Related: ADR 0007–0009, #23, #25, #27, #30.

## Problem
A signed and active JWT can continue to carry an authorization role after the identity administrator has removed it. Keycloak RFC 7662 introspection may report the role **as minted in the token**, not as currently assigned in the directory. An operator/provisioner/approver must not be admitted solely on that snapshot when changing tenant membership rights.

## Decision
- All `OrganizationApprovalWorkflow` `request`, `approve`, and `complete` paths require an `ICurrentOidcAccountDirectory` dependency; no optional fallback. After pinned signed JWT verification and fresh RFC 7662 token-status validation, require a **separate, fresh** account lookup matching the exact pinned issuer, validated `sub`, `enabled=true`, and the **currently effective realm role** (`platform_provisioner`, `platform_approver`, `tenant_admin` as appropriate). Any outage, mismatch, missing role, disabled/deleted user, malformed response or missing credentials prevents the SQL action.
- The Keycloak-specific adapter uses a **dedicated confidential service account** via `client_credentials`, not any caller's access token, to query `GET /admin/realms/{realm}/users/{sub}` and `GET /admin/realms/{realm}/users/{sub}/role-mappings/realm/composite`. The latter includes composite effective realm roles. Realm and user-ID values are validated before constructing the URL. No dynamic user-supplied URL, automatic redirect, cookie, positive caching or raw-token logging. Metadata/response size and timeouts bounded. HTTPS mandatory outside explicit loopback development.
- Never give the tenant API the directory service credentials. CLI requires `PROVISIONING_DIRECTORY_CLIENT_ID`, `PROVISIONING_DIRECTORY_CLIENT_SECRET`, and the pinned `PROVISIONING_OIDC_ISSUER` in addition to the confidential introspection client. Missing variables are a hard stop.
- The disposable Keycloak development fixture adds a separate service-account client; the CI setup script explicitly grants only `realm-management` `view-users`, `view-realm`, `query-users`, not `realm-admin` or `manage-users`. The CI also removes a user's role **after JWT issuance**, and checks that subsequent approval is rejected. It uses demo master-admin credentials to configure the fixture only; **never run that script in production**.
- Keep existing database approvals bound to exact subjects and organization/issuer scope, with independent SQL roles and atomic one-use consumption. Account checks do not make a cross-system transaction; no qualified audit evidence is implied.

## Limitations / required controls
- Query responses reflect Keycloak directory state at the query time, not a cryptographically signed assertion. A role/account can change between checks and the PostgreSQL commit (TOCTOU); production requires authorization freshness policy, entitlement-change monitoring/reconciliation, and independent audit.
- Roles are **effective realm roles**; client roles, group-derived access-control policies, temporary realm permissions and organizational approvals require distinct policy review. Production must independently verify the least privileges and network access of the directory service client.
- Dev service-account configuration, demo passwords and HTTP loopback must not be deployed in any production topology. Use TLS, secret vault, protected client authentication, rotation and operational IAM approval.
- Keycloak directory queries are not interchangeable with Microsoft Entra. Entra needs a provider-specific Microsoft Graph/role-assignment adapter (#28), not a guessed RFC 7662 or Admin REST URL.
- No verifiable human independent signoff, approved MFA/step-up (acr/amr), legally sealed approval evidence, tenant RLS, automated IdP tenant claim mapping or qualified QTSP status. Keep parent #27/#25/#23/#14 and #17 OPEN.

## Sources reviewed
- Keycloak Admin REST API (user and effective composite role mappings): https://www.keycloak.org/docs-api/26.4.7/rest-api/
- Keycloak Server Administration Guide (realm-management role grants): https://www.keycloak.org/docs/latest/server_admin/
- RFC 7662: https://www.rfc-editor.org/rfc/rfc7662
