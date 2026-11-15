# ADR 0025 — Fail-closed V013 registrar SQL issuance interlock until independently signed transaction

Status: accepted for **SECURITY INTERLOCK**, 2026-11-15. #51 child of #50/#46/#44/#38. Re-evaluate after real independent WebAuthn/FIDO2 registration, signed registrar approval, and atomic SQL authorization have been delivered.

## Context and threat

V013 grants `EXECUTE` on `public.issue_reviewer_registration_intent(text,text,text,text,text)` to `temporalmark_credential_registrar_group NOLOGIN`. V014 only strengthens RP DNS validation. #47/#48 verify two separate signed, MFA-fresh, active/current Keycloak principals; #49 exposes an isolated registrar-intent CLI and checks its narrow SQL LOGIN role membership, without seeding a credential. However **the SQL LOGIN itself can invoke V013 with arbitrary subject strings directly, bypassing all C# OIDC checks**. That DB-issued nonce is intentionally UNCONSUMABLE and has no trusted public key, attestation or approval. Even so, an accessible unsigned issuance entry point must not become a path to a future trusted credential.

## Security decision (deliberate behavior change)

1. V015 (forward-only, checksum preserving) **REVOKES EXECUTE** from the previously granted `temporalmark_credential_registrar_group` for V013's unconsumable function. Existing approver/provisioner/runtime roles and PUBLIC had no direct function EXECUTE. No login, member, key, credential, policy row or production OIDC client is created. Migration/schema owner retains its *normal PostgreSQL owner privileges* for controlled diagnostics, but cannot be treated as an independently witnessed human. V001–V014 remain byte-for-byte unchanged.
2. The formerly executable #49 `registrar-intent` CLI remains as test-driven policy/identity infrastructure but is explicitly **SUSPENDED**. The Npgsql store must detect the missing EXECUTE grant on the actual restricted session and deny before calling V013. No environment variable, CLI override or user-selected flag may reenable this permission; only a later signed-verification ADR plus versioned migration will enable a **new** narrowly scoped release path (preferably not the original arbitrary-subject signature).
3. Live PostgreSQL tests demonstrate a random dedicated LOGIN with membership in the NOLOGIN group **cannot** mint any nonce, cannot access policy/intent tables, and cannot bypass via old approver/provisioner/runtime group memberships. The schema owner's legacy V013 test remains (metadata only) with exactly the established one-ever uniqueness semantics; it does not register a signing key or approve an organization. No reissuance or recovery is introduced.
4. No signature verifier, human-approved FIDO2 credential, signed registrar release artifact, HSM, public registration endpoint, credential activation, atomic authenticated consume flow or legal WORM/QTSP status exists here. The real solution to #50 requires independently authenticated/registered signer credentials plus a signed original scope, replay-safe SQL transaction, real actor revocation, authorization audit and trust key lifecycle. PostgreSQL schema owners/superusers are trusted database administrators who may change privileges; no software privilege grant can prevent that.
5. On-prem and Azure have the same **disabled-by-default** behavior without any cloud or Keycloak demo privileges. Deployment instructions for #49 must explicitly warn that calling the isolated CLI will return DENIED until a future reviewed signed-release protocol is installed. The old direct APPROVE/REJECT SQL path is unchanged and remains a separate **release blocker** under #38.

## TDD and completion

Commit failing SQL/adapter tests first; add the immutable V015 script and update code/tests in subsequent commits. CI must apply fifteen checksum-verified migrations and pass all four exact-head jobs before closing #51. **#50, #46, #44 and #38 remain OPEN**. The original #49 completion is accurately described as *groundwork*, not an operational production registrar after the explicit security freeze.

Sources: PostgreSQL role and function permissions https://www.postgresql.org/docs/17/sql-revoke.html and https://www.postgresql.org/docs/17/sql-createfunction.html, WebAuthn registration https://www.w3.org/TR/webauthn-3/

## Standalone CLI stop-line test

The standalone operator executable denies `registrar-intent` **before any secret-file read, IdP request or SQL connection**, returning a fixed V015 suspension message and nonzero process status. CI checks that invoking with nonexistent token files and no registrar environment variables returns this exact interlock, **not** an unrelated missing-configuration error. This prevents operators from interpreting a successful JWT/MFA ceremony as permission to open an unsigned V013 SQL issuance path. It is intentionally impossible to reenable with environment variables; later approved signing requires a new reviewed command and SQL function.
