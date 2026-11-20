# Azure private-by-default web ingress — scoped #123

**Prequalification security control only.** This is not a deployed WAF, approved CAB change, private endpoint, proof of network isolation, GDPR DPIA, or eIDAS/QTSP qualification. See [ADR 0090](../adr/0090-azure-private-default-web-ingress.md), [#18](https://github.com/KeyserDSoze/TemporalMark/issues/18), [#115](https://github.com/KeyserDSoze/TemporalMark/issues/115) and [#113](https://github.com/KeyserDSoze/TemporalMark/issues/113).

## Security boundary

The Azure Terraform reference previously set `azurerm_container_app.web.ingress.external_enabled = true` unconditionally, publishing the web Nginx/PWA via the Container Apps environment's public endpoint even while managed ingress logs/WAF/CAB/security-review remain open. This is independent of successful private Nginx/#117 and API/#119 container logging regressions.

The new `enable_public_web_ingress` Boolean defaults to **false**. The web ingress stays **internal** unless an operator explicitly sets it `true`; the **API ingress is always internal**. Both web (port 80) and API (port 8080) keep `allow_insecure_connections = false`. The `frontend_url` Terraform output is **null when public web ingress is disabled** so an operator is not misled by a public-looking link. In the checked-in fictional `terraform.tfvars.example` the switch is explicitly false.

**Important limitations of the word internal:** Microsoft Azure Container Apps documentation distinguishes the *environment network accessibility* from the *individual app's ingress visibility*. With app internal ingress, calls are scoped to apps in the same Container Apps environment; it is **not** an automatic permit to reach the app from a developer workstation or all clients on the VNet. An external environment can still have a public endpoint, and other approved/routing resources can independently publish internal app traffic; the application switch does not lock down the whole environment or guarantee isolation from all possible routes. See [Azure ingress reference](https://learn.microsoft.com/en-us/azure/container-apps/ingress), [inter-container communication](https://learn.microsoft.com/en-us/azure/container-apps/connect-apps), and [Terraform resource](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_app).

## Plan-only CI evidence, no cloud access

CI runs a genuine `terraform test -no-color -filter=tests/ingress_boundary.tftest.hcl` on the pinned Azure reference with mocked `azurerm` provider and synthetic config values. The source tests assert:

- Web and API are both internal by **default**, with noninsecure ingress and correct 80/8080 target ports; output `frontend_url` is null.
- Setting **`enable_public_web_ingress=true`** in a mocked plan makes the **web only** external, while API remains internal and HTTPS-only.
- Setting `false` explicitly keeps both internal with no misleading public URL.

Existing plan-only checks for both OCI digest-pinned image references (#120, 11 scenarios) and Azure OIDC issuer syntax (#122, 17 scenarios) remain required. No actual Azure API calls, subscription, deployment, sensitive state or real network flows are exercised by these mock tests.

## Controlled release checklist

1. For disposable/prequalification installations **leave `enable_public_web_ingress=false`**. A browser outside the ACA environment should **not** assume direct reachability. If operator access is needed, design an independently reviewed private network entry or controlled gateway, and verify it in the target subscription.
2. For potential public exposure, first obtain independent security/privacy/CAB approval covering Front Door Premium/WAF or an approved equivalent, DNS/TLS/certificates, managed ingress/access diagnostic payload minimization, Log Analytics/export/retention, DDoS and pre-auth throttling, external proxy request-body/header handling, authentication/IdP registration, edge policy change/rollback and incident process. `enable_public_web_ingress=true` is a **change-controlled acknowledgement**, not executable enforcement of an authentic approval.
3. Confirm the Azure API **still has internal ingress**, that `allow_insecure_connections=false` on both apps, and the exact previously reviewed API/web OCI image digests and OIDC issuer are selected. Independently check WAF/ingress and platform revision with real Azure resources; the test mocks cannot prove anything about deployed networking.
4. Use a separately authorized Terraform workspace and protected credentials, plan/apply under approved release management, record the exact main SHA, manifests and deployment revision, then perform real outside/inside network reachability tests and synthetic URL/header/body log canary review against **all** managed ingress/log sinks. Inspect `frontend_url` only when public mode is intentionally enabled. Never paste customer JWT, document digest, secret connection strings or raw diagnostics into issue comments.

## Residual release stop lines

No Front Door/WAF, private-endpoint routing, Azure environment isolation, IP restrictions, managed ingress logging controls, production release approval, GDPR-DPIA/backup retention, Key Vault or token trust validation is introduced by #123. Public exposure when toggled is still **unprotected by a newly installed WAF**; do not do so in production without separate controls. Existing customer-facing on-prem OSS Compose is unaffected. The WebAuthn registrar V015/V016 freeze, unqualified timestamp evidence state `Unverified`, #17 independent signed WORM and #13/#15 eIDAS/QTSP qualification remain unresolved.

## Environment-level boundary added after #123 — scoped #124 / ADR 0091

The previous #123 control addressed **individual application ingress**, while an unset Container Apps environment `internal_load_balancer_enabled` could still allocate a publicly addressed environment. [#124](https://github.com/KeyserDSoze/TemporalMark/issues/124) now configures the **entire environment** with `internal_load_balancer_enabled = !var.enable_public_web_ingress`, using the same existing dedicated subnet. Default/explicit false = **internal environment and internal web/API apps**. Explicit true = **external environment + external web app**, while the API remains app-internal. Both apps still require secure connections. The original `frontend_url` remains null whenever the public opt-in is false.

A real **internal** Azure Container Apps environment needs independent DNS/network design for browser/operator access. Changing the internal/external environment setting on a previously created deployment can **replace** its environment; real Terraform plan and CAB-staged migration, data/rollback/DNS review are mandatory before applying to non-disposable resources. This is verified by mocked Terraform **plan assertions**, not Azure network probing, actual resource installation, WAF, regulatory qualification or approved ingress log retention. See [environment-specific operator guidance](AZURE_INTERNAL_ENVIRONMENT.md) and [ADR 0091](../adr/0091-azure-internal-container-app-environment.md). #18/#115/#113 remain OPEN.
