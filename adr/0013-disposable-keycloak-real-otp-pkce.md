# ADR 0013 — Real Keycloak browser OTP step-up / PKCE CI (not human four-eyes attestation)

Status: Accepted for disposable **integration tests only** (2026-11-15). Related #34, #31, #27, #25 and ADR 0009–0012.

## Context and decision

The existing provisioning pilot checks verified signed `acr` and `auth_time` plus live Keycloak account/role state, but the ordinary CI provisioning realm uses password grant and a tightly scoped, explicitly **non-MFA** exception. That is not a way to test actual two-factor execution.

Introduce a **second disposable realm** `temporalmark-mfa-ci`, mounted from a separate JSON import and isolated from the original PWA/provisioning Keycloak realm. It has a distinct demo approver and a public **Authorization Code + PKCE S256** client with a single exact localhost callback, no direct/password or implicit grant. The browser flow contains ordered *conditional* LoA levels: LoA 1 verifies username+password; LoA 2 verifies **OTP Form** with required execution, `loa-condition-level=2` and `loa-max-age=0`. The realm maps `urn:temporalmark:loa:2` to LoA 2. Client requires its minimum ACR; browser requests the same ACR as an **essential OIDC claim**, not just a non-essential `acr_values` hint. No SSO-cookie alternative is present in the CI flow.

The browser test creates a new password-authenticated session, performs required **TOTP credential enrollment** and deliberately discards that session's returned authorization code — **setting up a factor is not performing MFA**. A second fresh browser session must reach the OTP form after the password, refuse a deliberately invalid OTP and only succeed after verifying a generated RFC6238 code from a **new 30-second time step** (Keycloak rejects reuse of the enrollment OTP). The test then exchanges the code with a one-time PKCE verifier, validates the resulting JWT via the issuer's actual public JWKS, pinned audience/issuer and permitted algorithms, and checks current `acr`, `auth_time`, role and stable subject.

For the backend compatibility check, the signed access token is written only to an ephemeral owner-only file (0600) under GitHub's runner temporary directory and immediately removed by a shell `trap`. The **actual production-path .NET** `OidcAccessTokenVerifier` and `ApprovalAuthenticationPolicy` validate its signature and recent LoA2 ACR; the old disposable non-MFA exception is **disabled**. Passwords, OTP seeds/codes, bearer tokens and authorization codes must never be printed, published, recorded as trace/video/screenshot or included in exported artifacts. The test realm and fixture are **not a production identity policy**.

## Threat boundaries

- A browser automation generating a TOTP from a seed captured during test enrollment verifies that Keycloak **executed a password step and a correct second-factor verification** for the fixture. Since the automation itself holds both secrets, this is **not proof of independent human factor/device possession**, separate-person consent, regulatory MFA certification or hardware/phishing-resistant authentication.
- Any `acr` assertion is only as sound as its issuer's actual configured authentication flow. The test checks it **after a real OTP step**, and compares it to the Keycloak signed JWT; it does not trust a fabricated user attribute/hardcoded claim mapper.
- The real MFA test realm is a separate issuer. The production provisioning CLI still requires a **single issuer** for operator, intended tenant admin and reviewer; a full, audited real-user approval and independent consent ceremony requires #31. Do not mix realm credentials or bypass matching issuer checks.
- The minimum ACR and conditional LoA2 are deliberately short-lived (0-second LoA2 reuse for new authentication requests). A malicious/misconfigured production realm could still weaken policies; production needs audited IdP configuration, independent second-person review, secret vault, TLS, session management, risk-based controls and immutable independently signed evidence.
- The local realm uses seed demo credentials and HTTP loopback; it must never be deployed to production on-prem/Azure. Entra (#28) requires its own MFA assurance semantics. Database approval provenance (#33) is pilot-only, not WORM (#17), not legally qualified QTSP (#13).

## References
- Keycloak 26 step-up authentication and conditional LoA1/LoA2 flows: https://www.keycloak.org/docs/26.4.7/server_admin/
- OIDC Core ACR essential claim semantics: https://openid.net/specs/openid-connect-core-1_0.html
- RFC 7636 OAuth PKCE: https://www.rfc-editor.org/rfc/rfc7636
- RFC 6238 TOTP: https://www.rfc-editor.org/rfc/rfc6238
