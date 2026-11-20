# Internal-by-default Azure Container Apps environment — scoped #124

**Prequalification safety control only. Not a deployed network reachability test, WAF configuration, approved production change, managed-ingress log privacy assessment or qualified eIDAS/WORM claim.** Read [ADR 0091](../adr/0091-azure-internal-container-app-environment.md), prior [ADR 0090](../adr/0090-azure-private-default-web-ingress.md), the [Azure reference](../infra/azure/README.md), open [#18](https://github.com/KeyserDSoze/TemporalMark/issues/18) and log/privacy [#115](https://github.com/KeyserDSoze/TemporalMark/issues/115).

## Which boundary is private?

The initial Terraform reference set only the **per-app** web/API ingress `external_enabled`. Azure separately decides whether an entire `azurerm_container_app_environment` has a **public IP or an internal VNet load balancer**. The provider documents `internal_load_balancer_enabled=true` with an existing infrastructure subnet for the internal variant. The same resource previously left this environment property unset, potentially reserving a public-addressed environment even when neither app was meant to be published.

`main.tf` now explicitly uses:

```hcl
resource "azurerm_container_app_environment" "main" {
  # Other fields omitted; see actual file for full syntax.
  infrastructure_subnet_id       = azurerm_subnet.apps.id
  internal_load_balancer_enabled = !var.enable_public_web_ingress
}
```

The existing `enable_public_web_ingress` operator Boolean defaults to `false` and is shown disabled in the synthetic `terraform.tfvars.example`. **One** deliberate choice controls both related boundaries to prevent inconsistent state:

| Variable | Container Apps environment | Web ingress | API ingress | Public frontend output |
|---|---|---|---|---|
| Unset / `false` | Internal VNet load balancer | Internal | Internal | `null` |
| Explicit `true` | External/public environment | External | Internal | HTTPS FQDN |

Both apps retain `allow_insecure_connections=false`; the web target port stays 80 and the API target port stays 8080. These are two **different** meanings of internal. Microsoft documents that per-app internal ingress serves apps in the **same Container Apps environment**, not necessarily all clients on the VNet. Within an environment with an internal load balancer, a web app with external *app* ingress may be reachable **from the VNet**, not the public Internet; here web external and environment external are deliberately paired only in the public opt-in case.

## Test and production release procedure

The mandatory core Terraform job runs `terraform -chdir=infra/azure test -no-color -filter=tests/environment_boundary.tftest.hcl`, real Terraform `command=plan` using `mock_provider "azurerm"` and fictional credentials. It asserts **three scenarios**: (1) default private environment+both private apps, no misleading public URL; (2) explicit private stays private; (3) explicit web public sets environment external but API remains internally routed with HTTPS-only. Existing separate Terraform plan tests for per-app ingress (#123, 3), OCI SHA256 image digests (#120, 11) and OIDC issuer format (#122, 17) remain mandatory. **No Azure account, actual Container Apps revision, DNS resolution, VNet packet inspection, TLS certificate or apply is exercised by these mock plans.**

Before any approved non-CI Azure change, separately:
1. Confirm the required network design, IP range/subnet sizing, private DNS and controlled operator access from the approved VNet. A private-by-default environment may make the frontend **unreachable to ordinary Internet browsers**; this is intended until a reviewed route exists. Do not remove that boundary merely to simplify a smoke test.
2. Review the **real** Azure Terraform plan, provider version and preexisting environment state. Changing `internal_load_balancer_enabled` on an existing external/public environment can require **replacement**, with destructive recreation, new IP/FQDN/DNS changes and downtime implications. Do not assume an in-place toggle, automated cutover or rollback. Obtain explicit CAB-approved staged-migration and backups/recovery processes before applying changes to a non-disposable environment.
3. If an Internet-facing frontend is required, independently approve and implement **Front Door Premium/WAF (or equivalent)**, upstream access policy, TLS/DNS, protection against edge/pre-auth abuse, and platform/third-party ingress log minimization with real synthetic canary verification; review data protection (GDPR/DPIA), retention/deletion and incident handling. Only then consider `enable_public_web_ingress=true`. That variable **does not check CAB**, install a WAF or secure an exposed Azure endpoint.
4. Review the OCI digest release provenance, approved external OIDC issuer metadata/keys and build-time PWA OIDC authority, secrets/remote Terraform state, actual network ingress from **inside/outside VNet**, and the documented product functions/tenant isolation/restore. Retain proof in the separately controlled release register, not in personal-data-bearing GitHub logs.

## Remaining release gates

Azure environment networking is not a complete production network-security topology. No real Azure plan/apply, public/private route probe, Front Door/WAF, private endpoint, network policy, Log Analytics/managed ingress redaction, SIEM, Key Vault, CAB change, DR failover, archive/legal hold, QTSP/eIDAS audit or signed WORM custody is demonstrated. These remain OPEN #18/#115/#113/#17/#13/#15. The V015/V016 WebAuthn registrar freeze and `Unverified` pilot evidence state remain unchanged.

Sources: [AzureRM Container App Environment](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_app_environment), [Microsoft Container Apps networking](https://learn.microsoft.com/en-us/azure/container-apps/networking), [Microsoft Container Apps ingress](https://learn.microsoft.com/en-us/azure/container-apps/ingress).
