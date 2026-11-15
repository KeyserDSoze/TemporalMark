# Disposable Keycloak registrar + reviewer real MFA and live-directory CI (#48)

**CI/test-only, NOT a production WebAuthn credential registrar.** See [ADR 0023](../adr/0023-disposable-keycloak-registrar-browser-mfa.md), parent [#46](https://github.com/KeyserDSoze/TemporalMark/issues/46), [#44](https://github.com/KeyserDSoze/TemporalMark/issues/44), and [#38](https://github.com/KeyserDSoze/TemporalMark/issues/38).

## What the Docker CI proves

The existing `temporalmark-mfa-ci` realm (imported **only into the Docker development stack**) now has TWO different Keycloak accounts: one with `platform_approver`, one with `platform_credential_registrar`. Both must complete **a real browser password + TOTP** authentication, via public authorization-code PKCE-S256 clients with **different signed audiences**. Enrollment of the OTP seed is **NOT counted as MFA**: both tests discard the enrollment-session authorization code and require another clean browser session, refuse an incorrect TOTP, and only then exchange a state-bound code using its original PKCE verifier.

The resulting two bearer tokens are verified against the real Keycloak JWKS, pinned disposable HTTP-loopback issuer, matching role/audience, signed `acr=urn:temporalmark:loa:2`, `iat`, `auth_time`. The production .NET `OidcAccessTokenVerifier`, `KeycloakTokenIntrospector`, `KeycloakCurrentAccountDirectory` and `ReviewerCredentialRegistrarIdentityGate` then check BOTH users, real active RFC7662 introspection and fresh enabled-account/effective-realm-role status, without cached positive results. Wrong-audience token swapping is denied.

After the positive checks, disposable CI administration removes the registrar's current realm role; the *original* bearer must be rejected. Then it restores the role solely to isolate the disabled-account scenario, disables the registrar and verifies the *same* bearer is rejected. These test actions do NOT grant SQL permission or register a WebAuthn credential. Code cannot rely only on stale signed JWT claims.

### Local test-only controls

- Script: `tests/integration/configure-keycloak-registrar-mfa-ci.py prepare|remove-registrar-role|restore-registrar-role|disable-registrar`. It targets **only** `http://127.0.0.1:8081/admin/realms/temporalmark-mfa-ci` and master bootstrap test account. **Never** run it in an external or production realm. The confidential directory client has only `realm-management/view-users`, `view-realm` and `query-users` (no `manage-users`); a separate introspection client is scoped as token audience.
- Browser: `tests/frontend/mfa.spec.ts` and `registrar-mfa.spec.ts`, each with its own Playwright configuration. No traces, screenshots or videos and no stdout/stderr of passwords, OTP seeds, tokens or authorization codes.
- Tokens: ephemeral runner-owned `0600` files `TEMPORALMARK_CI_MFA_TOKEN_FILE` and `TEMPORALMARK_CI_REGISTRAR_TOKEN_FILE`, deleted by shell `trap` after test, never stored in GitHub artifacts.
- .NET: `tests/backend/TemporalMark.Provisioner.Tests/RealKeycloakRegistrarMfaEndToEndTests.cs` runs the original real backend adapters, not test-only fake introspection/directory data. Its negative phase is toggled **only** by `TEMPORALMARK_CI_REGISTRAR_EXPECT_DENIAL=true` after actual Keycloak role removal/disablement.
- `RegistrarIdentityGatePolicy` still requires a **real HTTPS issuer** unless the caller explicitly sets `allowDisposableMfaCiLoopbackHttp: true` **and** the issuer is exactly `http://localhost:8081/realms/temporalmark-mfa-ci`; other HTTP/loopback issuers stay blocked. That exception is solely for the hardcoded disposable Docker realm, never a production mode.

## What this does NOT prove or deploy

CI fixture accounts and built-in TOTP secrets do **not** establish independent physical custody, an approved human registrar, a production Keycloak MFA policy, a signed WebAuthn attestation/registered public key, verified human assent, or an accredited trust service. The business identity gate remains disconnected from SQL/CLI/API; it **cannot** call `issue_reviewer_registration_intent`. The `temporalmark_credential_registrar_group NOLOGIN` from V013/V014 still has **no login or membership**, and no new DB grants are introduced. No change was made to the existing direct SQL approve/reject route.

For real on-prem and Azure deployments, the platform owner must separately approve HTTPS identity issuer and RP FQDN, registrar/reviewer role governance and separate service credentials, actual strong MFA step-up configuration and recovery, independent trusted registrar SQL executor with transaction-bound nonce/replay controls (remaining #46), maintained FIDO2 attestation/registered credential store and revocation (#44), signed human reviewer decision and old direct SQL grant removal (#38). Cross-system Keycloak/DB time-of-check/time-of-use and token replay remain unsolved. Microsoft Entra requires a distinct provider-specific live/current role adapter (#28) and remains fail closed.

**No WORM/qualified QTSP status** or evidence of long-term validity is implied (#17/#13).

## Verification

The #48 issue must record the exact `main` commit and a successful **backend, frontend, terraform, docker-smoke** GitHub Actions run before closure, with test-first RED and completed GREEN evidence.
