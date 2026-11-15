# Registrar and reviewer dual-OIDC identity preflight (#47)

**Status: business-layer-only guard — not a registration service, authorization to call SQL, WebAuthn attestation, or independently witnessed consent.** See [ADR 0022](../adr/0022-registrar-dual-oidc-identity-preflight.md), issue [#47](https://github.com/KeyserDSoze/TemporalMark/issues/47), parents [#46](https://github.com/KeyserDSoze/TemporalMark/issues/46), [#44](https://github.com/KeyserDSoze/TemporalMark/issues/44) and [#38](https://github.com/KeyserDSoze/TemporalMark/issues/38).

## What the isolated code actually does

`ReviewerCredentialRegistrarIdentityGate.CheckAsync` is a .NET 10 business class, **not called by the CLI, API or PWA**. It requires two different access tokens from independently authenticated users, and a server-trusted expected reviewer subject:

- Validates each JWT through the existing `IVerifiedOidcTokenSource` (in production, `OidcAccessTokenVerifier`): signature, pinned HTTPS issuer, exact distinct audiences, expiry and freshness. Registrar role is exactly `platform_credential_registrar`; reviewer role is `platform_approver`.
- Requires an exact pinned, separately reviewed ACR and numeric `auth_time` + `iat` within 120 seconds **for both**. It reuses `ApprovalAuthenticationPolicy` with its password-only disposable fixture exception **always disabled**. A signed ACR is only an IdP claim: deployers must separately demonstrate that their Keycloak flow actually enforces MFA/step-up and that recovery does not downgrade it.
- For **both** identities, performs a fresh RFC7662 introspection through the existing Keycloak confidential adapter, checking active status, matching issuer, subject, audience and role. Then independently fetches enabled accounts and **current effective realm roles** from the separate Keycloak Admin REST adapter. No positive cache, JWT-only fallback, service-account role alias or HTTP self-registration.
- The issuer and two audiences are immutable, explicit constructor settings, not taken from an OAuth callback, tenant header or browser fields. The registrar and reviewer subjects must be distinct. If an original pending enrollment is involved, its **original privileged SQL-fetched** operator and first administrator subjects must be supplied together and neither principal may be one of them. Caller-supplied exclusion strings alone do not make the scope trusted.
- Returns only ephemeral issuer/subject/authentication-time preflight metadata, **not token values, signing public keys, registration attestation, a one-use grant, an approved registrar credential or human consent**.

Tests use test-only RSA signing keys with the production JWT verifier and controlled live/directory responses for mutation cases. Successful RSA fixture tests are **not** a real Keycloak registrar MFA browser test and do not prove separate human possession.

## What deployment must still implement (#46/#44)

**No registrar audience, role, Keycloak MFA flow, registrar service identity, SQL login/grant, or production client is automatically provisioned** by this class. Do not grant membership to the V013 `temporalmark_credential_registrar_group NOLOGIN` group merely because the preflight says yes; **no code path currently binds the identity result to V013 intent issuance**. This is intentional to avoid unsafe registration without reviewed authorization and replay-safe transaction semantics.

For on-prem, use explicitly configured HTTPS Keycloak realm, two independent protected confidential clients for introspection and directory lookup, verified effective realm roles and an audited true 2FA ACR policy. For Azure/Entra, the Keycloak-specific adapters must not be reused; the live introspection and current-role/disabled-user checks need a separately reviewed provider-specific implementation and trusted app-role configuration. No insecure localhost production exception; Keycloak's disposable password-grant accounts are not valid registrar credentials.

Future work must obtain current-role evidence *again* at the privileged boundary, independently bind the verified reviewer to a V013 unconsumable, owner-approved RP registration intent, and add an audited FIDO2/WebAuthn `navigator.credentials.create()` / attestation verifier, unique registered credential ID and COSE public key, key rotation/loss/revocation, explicit separate administrator approval and DB transaction consumption. Prevent stolen bearer replay and ensure Keycloak/DB cross-system TOCTOU is covered. Then #38 must verify real reviewer-held signed consent and revoke the historical direct approver SQL EXECUTE route, rather than using any OIDC-only result to authorize organizations.

## Security stop-line

There is **NO WebAuthn registered key or signature validation**, NO new public endpoint, NO SQL action, NO decision approval, NO legally sealed WORM evidence, and no assertion of qualified QTSP status. V013/V014, ADR 0021, and the on-prem/Azure [registrar intent runbook](WEBAUTHN_REGISTRAR_INTENT.md) remain applicable. #44/#46/#38 remain open.

Sources: [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662), [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html), [Keycloak realm authorization](https://www.keycloak.org/docs/latest/server_admin/), and [ADR 0022](../adr/0022-registrar-dual-oidc-identity-preflight.md).
