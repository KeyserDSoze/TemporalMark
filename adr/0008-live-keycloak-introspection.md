# ADR 0008 — Fresh, fail-closed Keycloak token introspection before tenant enrollment

Status: Accepted for development/pilot (2026-11-15)

Related: ADR 0007, #23, #25, #26.

## Context
A signed, unexpired JWT may still be revoked by the identity provider or belong to a disabled account. Provisioning administrators and first tenant administrators require a live authorization check **in addition to** the issuer-pinned JWT signature/audience/role/expiration verification already used by `TemporalMark.Provisioner`.

## Decision
- Extend the business port with `ILiveOidcTokenStatus.CheckAsync(accessToken, expectedAudience)`. The provisioning service requires this port in its constructor; it checks both the operator and initial administrator, and **only afterwards** attempts the atomic SQL bootstrap. No offline-only constructor, public HTTP provisioning API or opt-out flag exists. If IdP status is unavailable, ambiguous or inconsistent, refuse enrollment.
- Keycloak implementation uses **RFC 7662** via a dedicated confidential client, with HTTP POST form body (`token_type_hint=access_token`), HTTP Basic client authentication, issuer-pinned endpoint URL, bounded JSON response, six-second timeout, no cookies and no redirects. Never cache a positive live status; no token in URLs, logs or error messages.
- Require `active=true`, live `iss` and `sub` identical to the verified signed token, the expected `aud` and current introspection response containing the appropriate role. The business service never trusts an unvalidated `sub` from caller input.
- Keycloak's changing audience policy requires the **confidential introspector client** itself to appear in the target token `aud` as well as the business audience. The development-only realm fixture configures the mapper accordingly, without enabling compatibility bypasses.
- CLI requires `PROVISIONING_LIVE_PROVIDER=keycloak`, `PROVISIONING_INTROSPECTION_CLIENT_ID` and `PROVISIONING_INTROSPECTION_CLIENT_SECRET`; missing/unsupported provider is a hard failure, not fallback to JWT-only validation. Only the local development realm uses a committed **test-only** secret. All production secrets must come from a vault and should use stronger client authentication/rotation.
- Tests: fake live-status invariants, HTTP negative corpus (non-200, redirect, malformed/oversized response, inactive), full Keycloak CI real token issuance + disabled-account revocation and unchanged DB event count on denial.

## Limits and remaining controls
- RFC 7662 `active` reflects the IdP's interpretation and may not prove current role assignment or whether an account is locked separately from the token's state. A role in introspection may be a **snapshot from token issuance**, not a fresh directory lookup; independent account and role checks are part of #25.
- TOCTOU: the IdP token can be revoked after the check, even immediately before the SQL transaction; approval+strong authentication, explicit expiration window, change-control and reconciliation are necessary. This pilot cannot provide a global cross-system atomic transaction.
- This adapter is **Keycloak-specific**. Microsoft Entra has different validation and account-status surfaces (for example Microsoft Graph accountEnabled) and must have its own verified provider implementation; **do not claim Entra token introspection is available**. Fail closed rather than silently weakening the enrollment.
- This slice does NOT implement MFA step-up, four-eyes approval, fresh role lookup, production secret rotation, IdP claim synchronization, RLS or legally sealed audit. Keep #25/#23/#14 OPEN.
- Production must assess confidential client scopes, TLS, minimum permissions, intrusion/IdP failure response and operational incident escalation. No QTSP qualification is implied.

## Authoritative references
- RFC 7662 OAuth 2.0 Token Introspection: https://www.rfc-editor.org/rfc/rfc7662
- Keycloak OIDC endpoints/introspection: https://www.keycloak.org/securing-apps/oidc-layers
- Keycloak audience check change in 26.4.12+: https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/26.4/html/upgrading_guide/migration-changes
- Microsoft Graph user retrieval/account state: https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0
