# Disposable Keycloak MFA callback-port collision regression (#121)

**CI-only**, not production login configuration or a human MFA attestation. See [ADR 0088](../adr/0088-disposable-mfa-loopback-callback-fallback.md), [ADR 0013](../adr/0013-disposable-keycloak-real-otp-pkce.md) and open delivery parent [#20](https://github.com/KeyserDSoze/TemporalMark/issues/20).

## Failure that blocked Azure digest work

The exact final documentation-inclusive #120 commit `63d25c5f4d9831f273b7b9d5a6e816835cb707d4` had real Terraform mock-provider **11/11** image digest checks, backend **775/775**, frontend Playwright **4/4**, Docker real PostgreSQL **81/81**, full logical backup/restore **2/2**, Nginx/#117 and API/#119 log-canary tests and provisioning smoke all green. However [Actions 44643616282](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44643616282/attempts/1) failed early in the Keycloak browser MFA step with `EADDRINUSE 127.0.0.1:45678`, before a browser could perform authentication. Consequently `temporalmark/ci-4-core-jobs=failure` on that exact SHA, #120 remains OPEN; do not reuse an earlier green SHA to close it.

## Minimal, security-preserving CI repair

The **disposable** `temporalmark-mfa-ci` Keycloak client `temporalmark-mfa-pkce-ci` now has exactly three allowlisted HTTP-loopback redirect URIs, **no wildcard**: `http://127.0.0.1:45678/oidc-mfa-callback`, `http://127.0.0.1:46678/oidc-mfa-callback`, and `http://127.0.0.1:47678/oidc-mfa-callback`. The browser fixture tries those three local ports in order; it skips **only** `EADDRINUSE`, fails on other errors or if all three ports are occupied, and uses the selected exact URI in Keycloak authorization, callback parsing and code exchange. The registrar uses its separate unchanged 45679 callback.

The real Docker smoke now intentionally **binds 127.0.0.1:45678** before starting the reviewer MFA Playwright test using `tests/integration/run-mfa-with-blocked-primary-callback.py` (with `TEMPORALMARK_CI_MFA_FALLBACK=1`). This ensures that even on a clean runner the test exercises fallback to an **already registered** callback. The wrapper never examines tokens, authorization codes or TOTP seeds and closes its socket in `finally`. The previous test continues to require two distinct browser sessions (enrollment is not proof), invalid TOTP rejection, fresh RFC6238 TOTP verification, Code+PKCE S256, state/nonce binding, actual Keycloak JWKS-verified access token, exact signed `acr`/audience/issuer/subject and fresh authentication, with the 0600 test JWT file removed by workflow shell trap.

The backend CI source test `tests/integration/test_disposable_mfa_callback_fallback.py` requires identical browser port and Keycloak `redirectUris` allowlists, no open wildcard/no arbitrary ephemeral port, specific `EADDRINUSE` handling and actual forced-collision browser invocation. The RED-first failure is recorded in GitHub Actions for the preimplementation tests. Changing any production IdP, API endpoints, network exposure, SQL V001–V020 or V015/V016 security stop lines is **not** part of the repair.

## Operator and compliance exclusions

Do **not** copy the seeded MFA test realm, localhost HTTP callbacks, password/OTP fixture or demo credentials into production Keycloak/Entra. Port fallback is strictly for disposable CI reliability; it does not prove independent human possession, FIDO credential registration approval, CAB/AgID qualification, signed WORM custody or eIDAS qualified timestamps. See [Keycloak exact redirect URI guidance](https://www.keycloak.org/docs/latest/server_admin/index.html). Azure digest-pinned image release #120 still needs exact final SHA 4/4 CI; parent #20/#18/#115/#113, WORM #17, QTSP #13/#15, registrar #50/#44 and V015/V016 remain OPEN.
