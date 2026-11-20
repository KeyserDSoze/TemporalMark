# ADR 0088 — Enumerated loopback fallback for disposable real-MFA CI callback

Status: **Accepted for scoped CI-only #121 (2026-11-20)**. Related [#120](https://github.com/KeyserDSoze/TemporalMark/issues/120) (OCI Azure digest validation blocked by unrelated CI runner collision) and open parent [#20](https://github.com/KeyserDSoze/TemporalMark/issues/20).

## Baseline and failure

Reviewed [ADR 0001](0001-architecture-and-deployments.md), [ADR 0013](0013-disposable-keycloak-real-otp-pkce.md), `tests/frontend/mfa.spec.ts`, `registrar-mfa.spec.ts`, the Playwright `mfa.config.ts` and `registrar-mfa.config.ts`, `docker/keycloak/temporalmark-mfa-ci-realm.json`, `.github/workflows/ci.yml`, `docs/OPERATOR_PROVISIONING.md` and the exact final GitHub CI logs. [Run 44643616282](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44643616282/attempts/1) on `63d25c5f4d9831f273b7b9d5a6e816835cb707d4`: Terraform 11/11 mocked plan, backend/frontend, Nginx/API canaries, PostgreSQL 81/81 and full backup restore 2/2 SUCCESS; real MFA browser FAILED before authentication on `listen EADDRINUSE 127.0.0.1:45678`. This is a disposable CI callback socket collision; no failure in credential verification/PKCE or tenant isolation is evidenced by that aborted test.

Official [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/index.html) advises exact case-sensitive registered redirect URI matching, avoiding wildcards/full `*`, especially for security-sensitive clients. Production review and IdP policies must never be weakened to silence CI.

## Scoped decision

1. Keep the Keycloak realm **disposable and isolated**. For client `temporalmark-mfa-pkce-ci` explicitly register **three** local callback URIs only:
   - `http://127.0.0.1:45678/oidc-mfa-callback`
   - `http://127.0.0.1:46678/oidc-mfa-callback`
   - `http://127.0.0.1:47678/oidc-mfa-callback`
   Do not allow `localhost` wildcards, other hosts/paths, fragment/query variants, arbitrary ephemeral ports, private-network listeners or a production realm/IdP change. Registrar independently keeps its exact `127.0.0.1:45679/registrar-mfa-callback`.
2. In `mfa.spec.ts`, start a local HTTP callback listener via deterministic sequential binding to the three preapproved ports (loopback only). On `EADDRINUSE` alone continue; on any other error **abort**. If all ports occupied abort (never silently accept missing callback). Set the selected `redirect_uri` **after successful listener bind**, and use that identical value for every browser authorization request, callback URL parsing and authorization-code token exchange. Keep current independent freshly verified password+TOTP flow, invalid TOTP denial, one-time PKCE S256 and random state/nonce, JOSE signature/issuer/audience/current-ACR and subject checks. Continue refusing to record authorization codes, OTP, tokens, screenshots or trace; use 0600 token file and trap.
3. TDD RED-first source allowlist policy + real CI forced collision: a test wrapper binds **127.0.0.1:45678** in advance, then invokes the genuine Keycloak/Playwright MFA suite with the same signed-JWT backend follow-on already present. This guarantees the fallback path is exercised even on an otherwise idle runner, and tests that a CI auth client never redirects to an occupied port. The wrapper should never print or store credentials/codes, and must release the occupied port in `finally`. No need to run the entire MFA enrollment twice, which would make TOTP replay testing invalid. If the first port is already occupied by an unrelated runner process, proceed with the real MFA test; other whitelisted ports cover that case.
4. Make no change to V015/V016 reviewer registrar security interlock, the actual production API, Keycloak issuer/audience enforcement, database SQL migrations or Azure/on-prem runtime. This is a **reliability test fixture**, not evidence of independent human MFA possession or qualified eIDAS.

## Gate and nonclaims

RED before implementation must show CI source guard failing for missing binding fallback; the previous real EADDRINUSE run is further behavioral evidence. GREEN requires real forced occupied-primary-port Keycloak browser TOTP/PKCE signature verification, .NET signed ACR audience/current role, full 20-version SQL/Keycloak A/B, exact final documentation-inclusive main 4/4 CI, and Terraform 11/11 negative/positive image digest tests. Close only #121 and #120 if exact SHA checks succeed; #20/#18/#115/#113/#17/#13/#15 and the WebAuthn registrar freeze remain OPEN. No production IdP, CAB, QTSP, immutable custody or genuine human identity attestation follows.
