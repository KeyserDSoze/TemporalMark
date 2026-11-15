# ADR 0021 — Registrar-only unconsumable WebAuthn registration intent

Status: **accepted for an UNTRUSTED registration-intent pilot only** (2026-11-15).
Scope: #45 child of #44/#38. Follows ADR 0009–0020 and original unconsumable reviewer **decision** challenge V012. It is not a credential enrollment, WebAuthn attestation verifier or trust assertion.

## Context and objective

WebAuthn registration is a distinct, independently governed ceremony in which the relying party issues a random challenge and a browser returns an attestation response. A database-generated nonce, or a caller-supplied RP ID/public key, is **never** evidence that an approved reviewer possesses an authenticator. The current CLI still supports direct SQL reviewer approve/reject; a registrar SQL login must not create new signing authority or indirectly authorize tenants.

The next safe increment establishes a separately authorized **registration intent**, bound to a deployment-pinned RP policy, without installing a credential, public key or approval capability. It deliberately rejects all ordinary reviewer/provisioner/runtime SQL callers. The trusted human registrar, live IdP account/role/ACR enforcement and verified authenticator attestation belong to #44 follow-up and are **not** fulfilled by arbitrary SQL text.

## Decision

1. New immutable migration `V013__reviewer_registration_intent.sql` creates a **schema-owner-controlled** `reviewer_registration_rp_policies` table. Its rows bind exactly one approved HTTPS identity issuer, canonical lower-case ASCII DNS RP ID, exact origin `https://<rp-id>` (default HTTPS port only in this initial conservative profile), and a nonsecret change-control reference. **No default/fixture policy rows** are inserted: deployments fail closed until a reviewed migration-owner operation pins the exact issuer/RP under external change control. On-prem nonstandard ports, related origins and localhost are not supported by this first-registration slice; #40's broader policy cannot silently override this table.
2. `reviewer_registration_intents` is **append-only** with unique `(issuer, reviewer subject, rp_id)` for **one intent EVER per exact scope** until a reviewed migration introduces safe revocation/recovery/renewal. It contains a fresh PostgreSQL-generated 48-byte nonce, UUID, pinned issuer/RP/origin, distinct reviewer and registrar stable subjects, issued UTC, expiry <=2 minutes, protocol version 1. It holds **no credential ID, public key, attestation, COSE key, JWT, authentication secret, consumption flag, ACTIVE/APPROVED state or tenant data**.
3. A `temporalmark_credential_registrar_group NOLOGIN` role receives EXECUTE on only the narrow `issue_reviewer_registration_intent(issuer,reviewer_sub,registrar_sub,rp_id,origin)` SECURITY DEFINER function, with `SET search_path=pg_catalog, pg_temp`. Its function validates exact immutable owner-pinned policy, bounded nonempty distinct subjects, strict issuer, a 48-byte nonce from three PostgreSQL v4 `gen_random_uuid()` calls (approx. **366 effective random bits**, not 384 uniform random bits), unexpired <=120 seconds and single-use issuance. Prior provisioner/approver/runtime groups have no function EXECUTE or table SELECT/INSERT/UPDATE/DELETE. No registrar login or group membership is seeded in local Docker/CI; the migration owner retains elevated rights.
4. The policy and intent tables reject ordinary UPDATE/DELETE via triggers. This is **not WORM**: schema owners/superusers can drop triggers. Restrict migration-owner access, document change approvals, and require independent audit and sealed evidence for production.
5. This foundation is **intentionally unconsumable**. There is **no server endpoint, WebAuthn creation options UI, browser response verifier, registered credential registry, trusted reviewer key, or SQL routine activating a credential**. Owner/external registrar actions are **not** cryptographic evidence of a currently authorized registrar. When #44 introduces a genuine enrollment workflow, it MUST use independently authenticated registrar + reviewed reviewer, current effective roles, fresh MFA, a maintained WebAuthn/FIDO2 attestation verifier (not homegrown COSE/CBOR), and atomic one-time creation/approval and revocation. It MUST introduce a carefully authorized new consumption path rather than weakening this append-only table. No public self-registration or direct caller-key acceptance.
6. TDD: RED live PostgreSQL tests for denial/mismatched policy, role membership and direct table access, duplicate/parallel issuance, 96 uppercase hex nonce, deadline, immutability and **zero tenant or decision side effect**; GREEN migration and CI count updated to 13, no prior migrations edited. #45 closes only after exact-head four-job CI succeeds. Parents #44/#38, human consent #35/#31/#27 and legal/WORM #17/#13 remain OPEN.

## Operational stop-line and threat tradeoffs

The issuer/reviewer/registrar strings in SQL are **not yet verified JWT subjects**. NOLOGIN group cannot be used from ordinary application login, but any privileged owner can still issue. Independent registrar OIDC authentication, actual attestation, reviewer-held possession, key-loss/recovery, multi-device counter policy and atomic approval remain blockers. A stolen migration-owner credential can bypass append-only controls. The one-ever intent policy intentionally prevents silent reissuance after expiration; introducing safe renewal is a new, TDD-tested ADR, not a manual SQL bypass.

For Azure and on-prem, require independently approved HTTPS FQDN, matching signed Keycloak/Entra issuer, schema-owner change ticket, dedicated secret management and no seeded demo authorization. Neither environment gains production registration merely by applying V013.

## Primary sources

- W3C Web Authentication Level 3, §7.1 registration: https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-registering-a-new-credential
- PostgreSQL 17 SECURITY DEFINER and safe search_path: https://www.postgresql.org/docs/17/sql-createfunction.html
- PostgreSQL privileges and default EXECUTE grants: https://www.postgresql.org/docs/17/ddl-priv.html


## Forward-only V014 addendum — 2026-11-15

Subsequent RED PostgreSQL tests revealed the V013 initial RP regex would accept raw dotted IPv4, a >63-character DNS label and numeric-only final label; these are inconsistent with the strict .NET RP profile in ADR 0017. V013 was **already published and applied in CI**, so it is never rewritten. New versioned `V014__registrar_rp_dns_integrity.sql` adds an immutable SQL helper/constraint over owner-pinned RP rows to deny those names, and intentionally rejects existing incompatible owner policies on migration. No app/SQL credential activation or additional role grants are introduced. The exact migration count is **14**. Change-control and no-login boundaries are unchanged.
