# WebAuthn reviewer registration intent — V013 (pilot only)

**Not a credential enrollment, qualified WebAuthn signature, human authorization or legal evidence.** This schema-only groundwork is described in [ADR 0021](../adr/0021-registrar-only-unconsumable-credential-intent.md), scoped issue [#45](https://github.com/KeyserDSoze/TemporalMark/issues/45) and parent [#44](https://github.com/KeyserDSoze/TemporalMark/issues/44).

## Prerequisites and non-goals

- PostgreSQL 17+, versioned migrations through V014 executed via the **migration owner**. Earlier migration scripts and their SHA-256 checksums cannot be edited.
- The deployment's independently reviewed, exact **HTTPS identity issuer and RP hostname** must be approved by security/change control. This first profile pins an origin equal to `https://<rp-id>`, without explicit custom ports, related origins, HTTP localhost or browser-selected headers. Some on-prem nonstandard port setups will require a separately audited profile before enrollment.
- There is **no default trusted RP row** and **no registrar login or role membership** in the development stack. The group `temporalmark_credential_registrar_group NOLOGIN` does not gain possession or role assurance by its existence.
- No public registration/assertion API, WebAuthn library/attestation verification, approved key registration, credential store, key acceptance, registered counter, registration consumption or approved tenant decision is implemented. Existing restricted reviewer SQL approval/rejection functions remain a separate explicit blocker (#38).

## Change-controlled policy pinning (illustrative; owner only)

After an independently documented security change review, a separate privileged migration-owner session can create a **single append-only policy**. These sample names are fictitious, NOT an approved production policy:

```sql
INSERT INTO public.reviewer_registration_rp_policies
    (identity_issuer, rp_id, trusted_origin, change_reference)
VALUES
    ('https://identity.example.org/realms/review',
     'review.example.org',
     'https://review.example.org',
     'CAB-REVIEWED-2026-0001');
```

The identity issuer must be an explicitly approved issuer, not one chosen by a requester. The RP ID must be canonical lowercase ASCII DNS, and origin exactly HTTPS + RP ID in this migration. Policy rows reject ordinary UPDATE/DELETE via triggers, but a privileged schema owner can always alter the schema. Apply the existing security/change-control process before issuing any live credential workflow.

## Registration intent — intentionally unusable from the ordinary app

The SECURITY DEFINER `public.issue_reviewer_registration_intent(issuer,reviewer_subject,registrar_subject,rp_id,origin)` routine:
- Checks an existing pinned issuer/RP/origin and different stable reviewer and registrar subject strings.
- Creates an unpredictable server-side 48-byte nonce (approximately 366 effective random bits from three v4 UUIDs), one UUID and a maximum two-minute expiry.
- Permits at most **one issuance ever per exact issuer/reviewer/RP**; expiry does not permit silent retry or repinning, and no challenge consumption exists.
- Grants EXECUTE only to a **separate NOLOGIN registrar group with no seeded members**, not to runtime, organization tenant, approver or provisioner groups. All normal SQL groups lack SELECT/DML on policy and intent tables. Only a migration/schema owner can bypass this boundary.

The routine takes plain SQL subject strings. **It does not cryptographically authenticate a human registrar or reviewer**, and must not be exposed through HTTP or the existing CLI. A future service must authenticate the registrar against a pinned live/current Keycloak/Entra policy with independent signoff, verify the reviewer, issue signed RP-specific WebAuthn `create()` options and validate attestation through a maintained security-reviewed FIDO2 library. Do not take a user-supplied public key and call it approved.

## Planned work — #44 and #38 remain open

1. Independently govern registrar enrollment with separate identities, current IdP status/roles, strong fresh MFA, and explicit signed change approval. Define actual attestation trust policy, device custody, loss/rotation, recovery and audit evidence.
2. Use an audited WebAuthn library to verify an actual browser credential creation ceremony, challenge and RP/origin from immutable server storage, credential ID/COSE public key, authenticity and user verification. Enforce unique credential IDs across identities and prevent an end user from self-binding a public key.
3. Introduce a **new** TDD-reviewed, atomic consumed registration and later a separate assertion/decision path. Only subsequently change SQL reviewer decision privileges **with** a verified signature gate (#38). Audit migration-owner/registrar operations in independent WORM evidence (#17) and do not represent this as QTSP qualification (#13).
4. Preserve on-prem and Azure feature parity and explicit trust boundaries; never copy local Docker credentials/policies to production.

## Verification

- xUnit live PostgreSQL tests: `tests/backend/TemporalMark.Postgres.Tests/ReviewerRegistrationIntentPostgresTests.cs`.
- Expected versioned migration count in CI: **14**; `schema_migrations` provides checksum evidence.
- RED test-first commit `d213bb68f2daae58598de89e0fcf28866d195b52`; V013 implementation `9ef4550c9861fdaf4058a4e0fc8f6273868c7154`, CI version update `446a196b91cc1611818df1cbd5713493a00a612f`.
- See #45 for final exact-head CI result; never declare success without backend, frontend, Terraform and docker-smoke all green.

Sources: [W3C WebAuthn Level 3](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-registering-a-new-credential), [PostgreSQL SECURITY DEFINER](https://www.postgresql.org/docs/17/sql-createfunction.html), [privileges](https://www.postgresql.org/docs/17/ddl-priv.html).


## V014 RP DNS integrity hardening

The originally published V013 migration is immutable and must never be rewritten. Forward-only V014 adds a strict owner-pinned DNS constraint: reject IPv4 literal RP IDs, all-numeric final DNS labels and labels exceeding 63 characters, even if the earlier basic regex matched. Live PostgreSQL negative tests cover these failures. Existing bad policy rows stop the migration for change-controlled repair; do not disable the constraint. This correction **does not create or trust any WebAuthn credential**. Exact CI count: **14**.

## Follow-on to V013/V014 — dual-OIDC check only (#47; ADR 0022)

A separate non-authorizing business-layer identity preflight checks two signed, live, enabled and currently role-entitled Keycloak users with distinct pinned registrar/reviewer audiences and fresh IdP ACR. It is **NOT a caller of** `issue_reviewer_registration_intent`, does not provision a registrar SQL login or role membership, and cannot register a WebAuthn key. Keycloak real registrar MFA policy and a privilege-isolated, replay-resistant issuance service remain #46. Actual FIDO2 attestation, independent enrollment approval, credential revocation remain #44; signed reviewer decision and old SQL grant removal remain #38. See [ADR 0022](../adr/0022-registrar-dual-oidc-identity-preflight.md) and [identity guide](WEBAUTHN_REGISTRAR_IDENTITY.md).
