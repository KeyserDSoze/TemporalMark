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
- The API depends on SQL schema in `scripts/postgres-init/001_schema.sql`; private DB migrations must be executed from within the VNet after provisioning. No migration job is wired yet.
- A preconfigured OIDC authority and registered web/API clients are required. Tenant admin identities and memberships are not automatically enrolled on Azure.
- Database bootstrap credentials and a connection string currently enter Terraform state; a production implementation must use Key Vault/Managed Identity or an approved secrets flow with audited access and encrypted remote state.
- No HSM/TSU signer, trusted UTC(k) implementation, RFC 3161 issuing API, historical Trusted List verifier, signed manifest, independent immutable evidence writer, WAF, SIEM correlation or DR drill is provided yet.
- Blob immutability is intentionally **unlocked**; locking is irreversible. Obtain retention, privacy and CAB/legal approval before selecting and locking a production policy. The platform's initial indefinite retention policy is **not** fulfilled by the simple retention-days setting.
- Logs in Log Analytics have 30-day interactive retention, not legally sufficient evidence preservation.
- Azure pricing, scale, network segmentation, region, security posture and HSM choice require CAB/architecture review; Terraform creation alone proves no QTSP compliance.
- The API frontend is internet-facing without an application gateway/WAF in this reference, and container images must be scanned and pinned by digest for production.

For audit work consult `docs/COMPLIANCE.md`. Validate region-specific service SKUs and Terraform provider behavior before applying.
