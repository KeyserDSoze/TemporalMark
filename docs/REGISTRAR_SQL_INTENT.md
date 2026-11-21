# Registrar-only SQL registration-intent CLI — operator runbook (#49)

**CURRENT STATUS: SUSPENDED BY V015 SECURITY INTERLOCK. The `registrar-intent` command always denies before reading JWT files, contacting Keycloak or opening a database connection. The NOLOGIN registrar group has no EXECUTE on V013. The procedures below document previous development groundwork and MUST NOT be used to enable a registrar without a new independently signed, transaction-bound WebAuthn release.** See [ADR 0024](../adr/0024-isolated-registrar-sql-intent-workflow.md), [ADR 0021](../adr/0021-registrar-only-unconsumable-credential-intent.md) and parent [#46](https://github.com/KeyserDSoze/TemporalMark/issues/46).

## Strict operator prerequisites (on-prem and Azure)

Before use, an independent change approval/security review must record the **real HTTPS** Keycloak issuer, RP ID and exact origin `https://<rp-id>`, the selected reviewer stable subject, the independent registrar and reviewer roles, physical-factor MFA/ACR proof (step-up, recovery, disabled-user handling), and the V013 owner-pinned RP policy row + ticket. An HTTPS realm/TLS host and the database's migration owner are needed separately. **There is no automatic policy, trust anchor, LDAP/Entra service account, approver, registrar login, password or group membership** installed by these changes.

The separate `temporalmark_credential_registrar_group` is **NOLOGIN** with only function EXECUTE and no default members. A production database administrator, after CAB review and segregated operator approval, must independently create an application-executor LOGIN, with no superuser, CREATEDB, CREATEROLE, table DML/SELECT, or membership in the API/provisioner/approver roles, and grant it **only** the NOLOGIN registrar group. No SQL grant script is supplied for automatic deployment. A production dedicated LOGIN should be named `temporalmark_registrar_executor` and be restricted by PostgreSQL TLS, narrow network/host ACL and a vault-managed, short-lived rotated secret. The CLI requires that `session_user=current_user` exactly match its expected role, that the login has registrar-group membership, is nonprivileged, and has no direct rights on the RP policy or nonce tables.

**Threat and trust limitation:** A stolen dedicated registrar SQL LOGIN can call `public.issue_reviewer_registration_intent` directly, bypassing the dual OIDC CLI check. The function merely creates a short-lived, one-ever **unconsumable** intent. It cannot install a key or approve an organization. Release of a real credential-verifying service requires a stronger transaction-bound, independently witnessed registrar authorization and audit, separately tracked under #46/#44. Restrict database credentials to the operator host, vault and monitored change-control workflow; do not expose them in the API/PWA, general provisioning or Keycloak realms. PostgreSQL owner/superuser can bypass append-only triggers; they are not legal WORM.

## Environment configuration

All required variables come from **privileged deployment/operator configuration**, not CLI command arguments or browser data:

| Variable | Required intent |
|---|---|
| `REGISTRAR_LIVE_PROVIDER` | exactly `keycloak` |
| `REGISTRAR_OIDC_ISSUER` | explicit non-loopback **HTTPS** issuer |
| `REGISTRAR_AUDIENCE` | registrar token audience, e.g. `temporalmark-credential-registrar` |
| `REGISTRAR_REVIEWER_AUDIENCE` | distinct reviewer audience, e.g. `temporalmark-approval` |
| `REGISTRAR_REQUIRED_ACR` | reviewed actual password+MFA/step-up ACR, no disposable bypass |
| `REGISTRAR_APPROVED_REVIEWER_SUBJECT` | CAB-approved exact current reviewer subject |
| `REGISTRAR_RP_ID` | owner-pinned exact lowercase DNS WebAuthn RP ID |
| `REGISTRAR_ORIGIN` | exact `https://<rp-id>` (default 443, no suffix) |
| `REGISTRAR_INTROSPECTION_CLIENT_ID`, `REGISTRAR_INTROSPECTION_CLIENT_SECRET` | separate confidential Keycloak RFC7662 client |
| `REGISTRAR_DIRECTORY_CLIENT_ID`, `REGISTRAR_DIRECTORY_CLIENT_SECRET` | separate read-only current-user/effective-realm-role client |
| `TEMPORALMARK_REGISTRAR_DB` | **dedicated** vault-backed PostgreSQL connection (not owner, app, approver or provisioner) |
| `REGISTRAR_EXPECTED_SQL_LOGIN` | exact dedicated restricted SQL role, e.g. `temporalmark_registrar_executor` |

The exact reviewer subject is change-controlled deployment configuration. It is not automatically tied to an organization request; there is **no** signed transaction scope or verified FIDO2 key registration. Do not use arbitrary JWT claims or user-selected values as policy configuration. Failing role, issuer, RP, SQL login, MFA freshness, live RFC7662 or effective role checks denies the entire issuance. The CLI **never allows HTTP**, including the disposable Keycloak CI MFA issuer from ADR 0023.

## Standalone invocation (conceptual; no production deployment automatically enabled)

Run with the dedicated operator executable and two separately protected **owner-readable, mode 0600** token files, obtained after fresh independent Keycloak MFA login:

```text
TemporalMark.Provisioner registrar-intent --registrar-token-file /protected/registrar.jwt --reviewer-token-file /protected/reviewer.jwt
```

The command checks both real JWTs, distinct audiences/roles, exact ACR/auth_time, live RFC7662 and current enabled/effective directory roles before any SQL write. Then the independent, dedicated SQL connection calls the V013 function using *only* the verified issuer/subjects and pinned RP/origin. Output includes only the public-looking issuer, RP, subjects, UUID, expiry and a 96-hex challenge. Treat printed metadata as operationally sensitive; never upload tokens or SSH logs. It is a **nonce, not a key or legal evidence**.

The V013 database contract intentionally permits **one intent ever** for each issuer/reviewer/RP. If it expires or is lost, there is NO automatic second attempt or safe manual reissue. A future audited rotation/recovery ADR and versioned migration is required. Do not UPDATE/DELETE a prior intent or bypass uniqueness.

## Test and deployment scope

Business xUnit tests use controlled signed-claim/live/directory fakes to prove all gates precede DB writes. The PostgreSQL test temporarily creates a random restricted CI LOGIN, gives it just membership in the NOLOGIN group, checks actual Npgsql role/privilege restrictions, issues one nonce, denies duplicate replay and direct reads, then drops the login in `finally`. **No membership is committed by application migrations.** CI compiles the standalone CLI but does not execute real production HTTPS registrar or actual attestation; the disposable Keycloak browser MFA tests remain separate #48 tests.

On-prem must use independently managed TLS, vault/secret injection, offline recovery and monitor dedicated LOGIN. Azure must enforce a similarly segregated Azure Database for PostgreSQL role, Azure Key Vault-backed secret and approved private network access under CAB review. Both modes need further production hardening (#19/#18). Entra requires its own native live role/account checks (#28), not Keycloak confidential clients. WORM evidence and qualified status remain #17/#13.

A passing CI test is not proof of actual Keycloak production MFA, trusted credential signing, human review, legal preservation or timestamp qualification.

## Conflicting SQL role membership denial (#49)

The registrar executor also explicitly rejects membership in **any** existing `temporalmark_approver_group`, `temporalmark_provisioner_group`, or `temporalmark_runtime_group`, even if it otherwise holds the narrow registrar-function EXECUTE. Live PostgreSQL tests temporarily GRANT and REVOKE each conflicting group on the disposable executor and verify issuance is denied. Do not combine registrar with platform approval, general provisioning or API credentials. Neither role isolation nor OTP status establishes signed registration consent or eliminates direct-SQL credential bypass.

## V015 SECURITY INTERLOCK — REGISTRAR ISSUANCE SUSPENDED (#51)

**As of V015 the old `registrar-intent` CLI is intentionally NON-OPERATIONAL and always fails closed**. The migration revoked the V013 arbitrary-subject nonce function's EXECUTE privilege from the NOLOGIN registrar group. The .NET PostgreSQL adapter also refuses issuance even if a migration operator mistakenly regrants function EXECUTE directly to a registrar login. This supersedes the earlier #49 operator procedure above: it describes historical **development groundwork**, **not an available registrar service**. Do not create a registrar LOGIN or grant group membership for operations, do not bypass/revert/regrant V013 and do not use migration-owner credentials as a service login. No config flag, fallback local OTP or privileged SQL direct call is an acceptable release path.

The original V013 function remains callable by a migration/schema owner **only for separately approved diagnostic tests**; its nonce is still unconsumable, unsigned and cannot install a credential or approve a tenant. There is no WebAuthn registered key, verified attestation, independently signed human registrar consent, atomic replay-safe consumed authorization or WORM/QTSP certification. #50 requires a **different signed and transaction-bound registration release** before any production issuance may be re-enabled. Keep parent #46/#44/#38 open. See [ADR 0025](../adr/0025-fail-closed-registrar-sql-issuance-interlock.md); CI must prove exactly 15 immutable migrations and test that a stolen/legitimate registrar SQL login cannot mint a nonce.

## V016 additional direct-SQL regrant defense

V015's normal EXECUTE REVOKE is now accompanied by forward-only **V016**: a PostgreSQL owner-only INSERT trigger denies the underlying legacy V013 nonce-table mutation from a **nonowner SQL session**, even if an administrator accidentally grants that user direct V013 function EXECUTE. Tests temporarily GRANT the function to a restricted registrar, call V013 **directly** (bypassing the .NET CLI), and require SQLSTATE `42501` and zero minted rows. Do not drop the trigger or create a service login as a workaround. Owner/schema-administrator access is still inherently privileged, and this does not verify WebAuthn signatures, consent or a qualified service. Current checksum migration count: **16**, not the historical 15 from the initial V015 stop-line.

## Legacy registrar SQL EXECUTE drift and V015/V016 interlocks (#147)

The V015 `REVOKE EXECUTE` on `public.issue_reviewer_registration_intent(text,text,text,text,text)` for the registrar group and V016 owner-only INSERT interlock remain mandatory and **unchanged**. A future operator could mistakenly `GRANT EXECUTE` on this **SECURITY DEFINER** function directly to the API SQL runtime LOGIN without restoring forbidden group membership. [ADR 0112](../adr/0112-privileged-function-execute-postgres-prelisten.md) / [#147](https://github.com/KeyserDSoze/TemporalMark/issues/147) add an additional **candidate-only prelisten PostgreSQL effective EXECUTE deny** to flag that SQL ACL drift *before HTTP listen*. A distinct generated SQL LOGIN test on real PG17 [RED 44942023228](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44942023228) proved the missing check, without calling the registrar function, altering a registration intent or changing the V015/V016 SQL interlocks. The minimum source-only patch is [`4877bc0`](https://github.com/KeyserDSoze/TemporalMark/commit/4877bc003c7a9798f10035bf0ca67a095638c580).

This does **not** enable registrar enrollment, validate a genuine reviewer WebAuthn key, remove requirement for independent signed MFA-fresh registrar authorization or change live default Password mode. The CLI remains SUSPENDED and #50/#44/#46/#128 remain OPEN; no WORM or QTSP qualification attested.
