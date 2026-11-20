# Azure OIDC issuer syntax gate — scoped #122

**Pre-qualification pilot only.** Terraform validation is **not proof of a trustworthy IdP, approved human enrollment, regulatory MFA or qualified eIDAS timestamping**. Read [ADR 0089](../adr/0089-azure-oidc-issuer-input-validation.md), [ADR 0001](../adr/0001-architecture-and-deployments.md), the [OIDC provisioning operator guide](OPERATOR_PROVISIONING.md) and open [#18](https://github.com/KeyserDSoze/TemporalMark/issues/18), [#25](https://github.com/KeyserDSoze/TemporalMark/issues/25), [#115](https://github.com/KeyserDSoze/TemporalMark/issues/115).

## What Terraform accepts and rejects

`var.oidc_authority` configures `Authentication__Authority` in the .NET 10 Azure API Container App. Previously Terraform only checked the prefix `https://`, allowing malformed, ambiguous or local values. It now requires **HTTPS**, a plausible lowercase DNS FQDN with at least two labels and alphabetic final label, optional explicit numeric port and optional nonempty path segments. Examples of accepted **formats** (neither is an approved actual issuer):

```text
https://id.example.org/realms/approved-tenant
https://login.microsoftonline.com/01234567-89ab-4cde-8123-456789abcdef/v2.0
```

The `terraform -chdir=infra/azure test -no-color -filter=tests/oidc_issuer.tftest.hcl` suite exercises a **mock `azurerm` provider with `command=plan`**, three accepted issuer formats and fourteen rejected ones: plaintext HTTP, missing host, `localhost`, IPv4 addresses, embedded user/password, deceptive `host@other-host`, URL query, fragment, trailing slash, whitespace, `..` traversal, empty path segment and single-label host. These tests use only fictional domains/OCI digest images and synthetic credentials; there are **no Azure API calls or applies**. The earlier `tests/image_pins.tftest.hcl` OCI digest policies remain mandatory.

This deliberately narrow input syntax also excludes internationalized host names, IP literal/IPv6 hosts, escaped issuer paths and some legitimate path encodings. A future exception requires an independently assessed ADR and real OIDC metadata comparison; **do not simply change back to `startswith` or add arbitrary regex alternatives to pass a production deployment.**

## Operator steps before any deployment

1. Select and approve an **exact, tenant-specific issuer** through governed IdP enrollment. A URL with valid syntax, including a generic multi-tenant or attacker-controlled hostname, does **not** demonstrate that an OIDC account is trusted. Capture out-of-band approved hostname, tenant/realm, HTTPS certificate trust, auth flows, role mapping and change control; do not treat generic `common` or disposable test realms as approved production tenants.
2. From a separately authorized network, retrieve real OpenID Provider Configuration over trusted HTTPS at the issuer-specific `/.well-known/openid-configuration` and compare its **`issuer` string exactly** to the approved `oidc_authority` (no implicit trailing-slash normalization or case folding). Inspect the discovered `jwks_uri`, signing key policy, algorithm restrictions, expected audiences, required MFA `acr` and current-directory account revocation behavior. Do not log bearer tokens, OTP, tenant subjects or secret discovery responses.
3. Independently confirm the web image's **build-embedded `VITE_OIDC_AUTHORITY`** matches the intended issuer and client redirect registrations. Azure API `Authentication__Authority` is a runtime variable, but the web authority is compiled into the pinned OCI image. The #120 image digest must still point to the **approved** registry manifest for that environment. Verify real signed user JWTs, 401/403 tenant isolation, live role/account revocation and owner-independent registration gates; the mock Terraform tests cannot do that for a deployed tenant.
4. Run `terraform -chdir=infra/azure fmt -check -recursive`, `init -backend=false`, `validate`, then both mocked tests. Review any real Azure `plan` and deploy only with approved IdP configuration, protected secrets/state, WAF/ingress/logging/DPIA and CAB change control. Do **not** deploy the `terraform.tfvars.example` fake credentials or image digests.

[OIDC Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) requires the issuer to be an HTTPS URL with host, optional port/path, no query/fragment, and exact metadata issuer matching. [HashiCorp variable validation](https://developer.hashicorp.com/terraform/language/block/variable) documents plan-time rejection. The syntax gate is **not** a verifier of DNS resolution, registry of approved issuer hosts, TLS identities, JWT provenance, Keycloak/Entra production role registration, upstream proxies or Azure managed ingress privacy.

**Still OPEN:** production #18/#25/#28/#31 (actual IdP/Entra assurance, issuer trust and account state), #115/#113 (Azure ingress/Log Analytics and GDPR/DPIA retention), #17 (independent WORM) and #13/#15 (eIDAS/QTSP qualification). V015/V016 reviewer/registrar interlocks stay frozen and pilot evidence remains `Unverified`.
