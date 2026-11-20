# Azure Terraform reference — pre-qualification ONLY

This stack lays out a **reference development architecture** using native Azure services: resource group, VNet, delegated subnets, private PostgreSQL Flexible Server, versioned Blob evidence container with an **unlocked** immutability policy, Log Analytics, Container Apps API/web with system-managed identity, and RBAC.

## Prerequisites
Azure subscription with resource-provider registrations; Terraform >=1.8; Azure CLI credentials, Azure Container Apps and PostgreSQL quota. Build and publish images separately. The web image embeds `VITE_OIDC_AUTHORITY` at build time; it must match the target public HTTPS OIDC issuer. Provide a valid tenant-aware OIDC provider, not development Keycloak.

```sh
cd infra/azure
cp terraform.tfvars.example terraform.tfvars
# Replace example strings; use secure secret injection, never commit real passwords.
terraform init
terraform plan
terraform apply
```

**Important pilot limitations / blockers:**
- The API requires **versioned SQL migrations** in `scripts/migrations` (see `docs/DATABASE_MIGRATIONS.md`); the separate `scripts/apply-migrations.sh` runner must be run from within the VNet after provisioning. A production Azure migration job is **not** wired yet; `scripts/postgres-init/` is a development fixture, not an Azure upgrade mechanism.
- A preconfigured OIDC authority and registered web/API clients are required. Tenant admin identities and memberships are not automatically enrolled on Azure.
- Database bootstrap credentials and a connection string currently enter Terraform state; a production implementation must use Key Vault/Managed Identity or an approved secrets flow with audited access and encrypted remote state.
- No HSM/TSU signer, trusted UTC(k) implementation, RFC 3161 issuing API, historical Trusted List verifier, signed manifest, independent immutable evidence writer, WAF, SIEM correlation or DR drill is provided yet.
- Blob immutability is intentionally **unlocked**; locking is irreversible. Obtain retention, privacy and CAB/legal approval before selecting and locking a production policy. The platform's initial indefinite retention policy is **not** fulfilled by the simple retention-days setting.
- Logs in Log Analytics have 30-day interactive retention, not legally sufficient evidence preservation. **V020/#118 adds an owner-only manually executed SQL function** to purge idle subject/tenant rate-counter rows on the shared PostgreSQL 17 primary (see [operator runbook](../../docs/IMPRINT_RATE_COUNTER_CLEANUP.md)); Terraform does **not** install a maintenance scheduler or approve a retention/DPIA policy. SQL owner credentials and schema migrations need independent change control. The **shared frontend Nginx image** uses an explicit minimal stdout access format (only HTTP status, method and duration), with a disposable Docker image/live HTTP privacy regression documented in [Nginx access-log runbook](../../docs/NGINX_ACCESS_LOG_PRIVACY.md) / ADR 0084. The shared .NET 10 API binary also filters normal ASP.NET Core request diagnostics and registers zero-field HTTP logging options (#119; [API diagnostics runbook](../../docs/API_LOG_PRIVACY.md)) and is tested separately using fake request canaries on the running Docker API. **Azure Container Apps managed public ingress/access telemetry, API warning/error/exception logs, external WAF/CDN/gateway, Nginx error logs, Log Analytics collection and backup retention were NOT tested or approved by these container-only changes.** Independently inspect deployed images, every effective ingress/log sink, body/header capture and legally approved deletion/DPIA before deployment; #115/#113 remain OPEN.
- Azure pricing, scale, network segmentation, region, security posture and HSM choice require CAB/architecture review; Terraform creation alone proves no QTSP compliance.
- The API frontend is internet-facing without an application gateway/WAF in this reference. **Scoped #120 / ADR 0087 now rejects mutable API/web image tags at Terraform PLAN time:** both image input variables require lowercase OCI SHA-256 manifest digests (`registry/repository@sha256:<64 hex>`). Plan-only mocked-provider Terraform CI checks 11 success/negative cases. The sample `.tfvars` digests are deliberately FAKE and must be replaced using a reviewed manifest digest obtained from the real registry after publishing. See [Azure image digest release guide](../../docs/AZURE_OCI_DIGEST_IMAGE_GUARD.md). **This does not verify OCI publisher signatures, SBOM/provenance, image vulnerabilities, Azure runtime pull/revision, private ACR identity, production rollout or CAB approval**; those remain under #18/#115.

For audit work consult `docs/COMPLIANCE.md`. Validate region-specific service SKUs and Terraform provider behavior before applying.
