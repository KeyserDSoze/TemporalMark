# ADR 0024 — Isolated registrar intent workflow with dedicated SQL executor

Status: accepted for NON-AUTHORIZING registration-intent issuance only (2026-11-15), child #49 of #46/#44/#38. Consult ADR 0010–0011 and ADR 0021–0023.

## Security context

V013/V014 create owner-pinned HTTPS issuer/RP/origin policies, unconsumable one-ever short-lived registration intents, and a NOLOGIN registrar group with zero seeded members. ADR 0022/0023 verified two independently authenticated Keycloak users, real password+TOTP/OIDC PKCE, actual RFC7662 and current directory roles. A nonce is not a WebAuthn credential. A stolen registrar SQL login could still directly invoke the issuance function without the application's OIDC gate. This remains a production trust risk until reviewed service credential custody, issuance attestation and transactional ceremony consumption are implemented.

## Decision

1. Add a .NET 10 business ReviewerRegistrationIntentWorkflow, which accepts only two independently signed and fresh Keycloak registrar/reviewer tokens, passes them to the concrete ReviewerCredentialRegistrarIdentityGate, and only then calls an IReviewerRegistrationIntentStore. The immutable deployment policy pins exact HTTPS issuer, lowercase DNS RP ID, strict origin equal to https:// + RP ID, and an independently approved reviewer subject. No browser/CLI argv header/tenant selects trusted issuer/RP/reviewer. No organization request is bound by this first generic credential-registration intent.
2. Pass only the OIDC-gate-confirmed issuer, distinct registrar and reviewer stable subjects, pinned RP/origin to SQL. Accept only the first and sole returned nonempty intent UUID, uppercase 96-character hex challenge (48 bytes), timestamp and <=2-minute TTL; no SQL result can be called authorization. The existing one-ever uniqueness constraint denies reuse/concurrent attempts; it intentionally does not provide a reusable registration mechanism or a consumed WebAuthn ceremony.
3. Add PostgresReviewerRegistrationIntentStore using Npgsql on a separately configured NpgsqlDataSource. Before execution, fail unless session_user=current_user=the explicitly configured dedicated SQL login, its role is neither superuser nor CREATEROLE/CREATEDB, it is a member of the narrow registrar NOLOGIN group, and it has no direct SELECT/INSERT/UPDATE/DELETE on either V013 table. Reject owner and old API/provisioner/approver credentials. Use parameterized SQL and check cardinality; do not pass JWTs, TOTP, public keys or secrets to SQL. No V001–V014 changes.
4. Add registrar-intent to the standalone operator CLI, not an API/PWA endpoint. Demand two protected 0600 JWT files and explicitly configured registrar HTTPS issuer, distinct audiences, exact pinned ACR, confidential live introspection and directory clients, approved reviewer subject, exact pinned RP and origin, dedicated registrar DB connection and expected SQL login. Do not reuse provisioning or approver DB identity or permit the disposable HTTP/password-only exception.
5. No login, registrar NOLOGIN-group membership, default RP policy, registration key or trust is automatically created. Test a disposable random CI SQL account with narrowly granted group membership, then delete it; production requires separate CAB approval and vaulted secret rotation. A compromised dedicated SQL login could bypass application identity checks; keep issue #46 OPEN for stronger transactional signed authorization and real-world registrar service custody.
6. Never infer registered WebAuthn credentials, FIDO2 attestation, human consent, APPROVE/REJECT permission, challenge consumption, legally sealed evidence, WORM or QTSP qualification from this code. #44/#38/#35/#31/#17/#13 stay OPEN.

## Test and release requirements

Commit RED business and PostgreSQL integration contracts before implementation; GREEN separate workflow, Npgsql adapter and restricted standalone CLI. Verify exact final main SHA backend/frontend/Terraform/docker-smoke success before closing #49. The underlying registrarial trust and production-role approval are not CI-certifiable.

References: https://www.postgresql.org/docs/17/ddl-priv.html ; https://www.postgresql.org/docs/17/sql-createfunction.html ; https://www.rfc-editor.org/rfc/rfc7662 ; https://www.w3.org/TR/webauthn-3/

## Test-driven group-separation hardening (2026-11-15)

The initial store guard prohibited broad direct table privileges, but that alone did not prevent a dedicated registrar login from ALSO being a member of the legacy approver/provisioner/runtime groups. RED PostgreSQL tests (`c5e2501`) explicitly GRANT each conflicting role to the otherwise valid temporary registrar executor and require SQL issuance to fail before any additional nonce is created. GREEN `fe5e38d` adds three actual membership checks on the opened SQL connection and rejects **any** conflicting approver, provisioner or runtime group. CI revokes each simulated grant and finally drops the disposable login; migrations still seed no member or LOGIN. This is defense in depth and does not solve a stolen legitimate registrar SQL credential bypassing the OIDC gateway.
