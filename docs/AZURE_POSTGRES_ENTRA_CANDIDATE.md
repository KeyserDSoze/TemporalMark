# Azure PostgreSQL — isolated Entra-only, no-password candidate (#129)

**PREQUALIFICATION TEST-ONLY. DO NOT APPLY IN AZURE. Not a migration runbook or production authorization.** See [ADR 0095](../adr/0095-isolated-entra-only-postgres-candidate.md), [#129](https://github.com/KeyserDSoze/TemporalMark/issues/129), open [#128](https://github.com/KeyserDSoze/TemporalMark/issues/128), and parent [#18](https://github.com/KeyserDSoze/TemporalMark/issues/18).

## What this candidate does and does not do

The existing `infra/azure/main.tf` **still configures** the active Azure PostgreSQL reference server with `var.postgres_admin` / `var.postgres_password`. The latter enters current Terraform state, and older state or snapshots may contain previously embedded API connection strings too. **This candidate does not remove either risk from the running reference.** It lives in a **separate Terraform root**, `infra/azure/candidates/entra_postgres/`; it is **not** instantiated by the current Azure module, CI does no `apply`, and no old server or database is migrated, recreated, imported or replaced.

The candidate defines only a *new*, distinct `-entra-candidate` PostgreSQL 17 Flexible Server using an externally provided existing delegated VNet `postgres` subnet and a private PostgreSQL DNS zone, `public_network_access_enabled=false`, `authentication.active_directory_auth_enabled=true`, `password_auth_enabled=false`, explicit approved Entra tenant GUID, and **no `administrator_login` nor `administrator_password`**. It declares one Microsoft Entra **Group** administrator by approved object GUID and name and one separate `temporalmark_candidate` database created after administrator assignment. This is a Terraform **control-plane configuration candidate**, not an app-connected or migrated SQL registry.

Input validation rejects invalid subscription/tenant/group IDs, server names without the distinct candidate suffix, unapproved subnet/DNS ARM formats, a different resource group/subscription in the referenced network components, and a group object ID equal to the tenant ID. The Azure provider cannot establish from a mock plan that an actual VNet subnet **is delegated**, that DNS is linked/reachable, that a group **exists and is controlled by humans**, that a server principal can acquire a token or that the database roles/ACLs match the application.

## CI-only verification

From the repository root, with the same reviewed Terraform and AzureRM versions:

```sh
terraform -chdir=infra/azure/candidates/entra_postgres fmt -check -recursive
terraform -chdir=infra/azure/candidates/entra_postgres init -backend=false
terraform -chdir=infra/azure/candidates/entra_postgres validate
terraform -chdir=infra/azure/candidates/entra_postgres test -no-color -filter=tests/entra_only_candidate.tftest.hcl
```

The mandatory GitHub Terraform job performs candidate `init -backend=false` and **mock-provider** `terraform test` independently of the existing Azure root (existing OCI, OIDC, private web/environment, Blob, Key Vault tests remain). CI uses **invented UUIDs and fake resource IDs**, never a real subscription or Entra identity, and performs no Azure management-plane or PostgreSQL data-plane connection. Terraform fmt/validate and plan tests are **not** evidence of a successful Azure deployment.

## Separate real deployment/cutover prerequisites — remain OPEN #128/#18

1. Independently approve a **new and distinct server**, target region/subscription, Entra tenant, Group ownership and administrative membership, delegated subnet/private DNS link and managed identity/service-principal prerequisites; approve an authorized private runner, state/backend/backup custody, HA/DR, migration plan and break-glass process. Group Object ID and tenant Object ID must be verified in the live directory, not inferred from regex.
2. Before any auth-mode change to an **existing server**, inventory database roles and grants, migration-owner DDL, the restricted provisioning/reviewer/registrar SQL logins, connection pooling and current application credentials. The 20 immutable SQL migrations are run by `scripts/apply-migrations.sh`, which still expects `PGPASSWORD`; the Npgsql API presently expects a conventional connection string via a Key Vault secret reference. **Neither becomes Entra-token-aware from the Terraform change.** Token acquisition, short-lived expiry/refresh, TLS certificate validation, privilege parity, current-role revocation and fail-closed restarts need explicit implementation and tests.
3. Design an independently approved Entra administrator ceremony and lower-privilege Entra database roles. Microsoft notes that enabling Entra may restart the server; administrator provisioning precedes DB-user configuration and data owner assignment. Do not mistake Azure RBAC resource permissions for PostgreSQL DML/DDL authorization. Test real Entra token acquisition and renewals, SQL migration one-shot runner, multi-tenant API authorization, audit logs and rollback on a **disposable staging server** with backups.
4. Treat old Terraform states, CI/deployment histories, storage snapshots and database passwords as potentially exposed, protect access and rotate safely under approved retention/privacy/legal-hold rules. Test full restore, old/new credential disablement, failed migration rollback, independent authorization and availability. Do not delete the existing server, revoke SQL access abruptly or scrub retention-protected evidence under this candidate issue.
5. Only after real end-to-end Azure proof and CAB/security/DB-owner approval may a **separate** ADR specify a safe change to `infra/azure/main.tf` / application PostgreSQL authentication, with a non-destructive state migration strategy and all original identity and tenant isolation guarantees maintained.

Official references: [Microsoft Entra PostgreSQL authentication concepts](https://learn.microsoft.com/en-us/azure/postgresql/security/security-entra-concepts), [configuration](https://learn.microsoft.com/en-us/azure/postgresql/security/security-entra-configure), [managed identity connectivity](https://learn.microsoft.com/en-us/azure/postgresql/security/security-connect-with-managed-identity), [AzureRM PostgreSQL Flexible Server](https://registry.terraform.io/providers/hashicorp/azurerm/4.44.0/docs/resources/postgresql_flexible_server) and [AzureRM Entra admin](https://registry.terraform.io/providers/hashicorp/azurerm/4.44.0/docs/resources/postgresql_flexible_server_active_directory_administrator).

**Legal and platform status unchanged:** independent WORM/retention #17, public/WAF/privacy/DPIA #115/#113, own qualified service #13/#15, WebAuthn V015/V016 and Azure #18 remain OPEN. This artifact does not certify eIDAS, QTSP, data custody, Azure token exchange or production availability.

## Next .NET candidate (#130) — not deployed or connected

After the isolated Entra-only server Terraform root #129, the reusable `EntraPostgresDataSourceCandidate` in `TemporalMark.Infrastructure.Postgres` now tests strict Azure PostgreSQL DNS/TLS, missing-password denial and scoped async managed identity token supplier with Npgsql 10. See [ADR 0096](../adr/0096-detached-npgsql-entra-token-candidate.md) and [Npgsql runbook](ENTRA_POSTGRES_NPGSQL_CANDIDATE.md). **Neither candidate is instantiated by the current Azure Terraform nor wired to the current API/Provisioner/SQL migration job.** No live Azure token, PostgreSQL role, private network, backup/migration or credential removal is established; #128/#18 remain OPEN.

## Distinct PostgreSQL runtime UAI in the isolated root (#132 / ADR 0098)

The same **non-applied, non-imported** candidate root now declares one separate `azurerm_user_assigned_identity.postgres_runtime_candidate` for a **future** least-privilege PostgreSQL runtime service principal, with required explicit lowercase `postgres_runtime_identity_name` ending `-pg-mi-candidate`, fixed candidate-only/NOT_QUALIFIED/no-auto-deploy tags, approved existing RG and region and `prevent_destroy`. Three **non-secret computed** outputs identify its ARM resource ID, application/client GUID, and Entra service principal object GUID. A real Azure apply and independent post-creation directory/SQL verification are still required: mock plans do not know actual IDs or grants. This does **not** attach identity to a Container App, grant Azure RBAC, create any PostgreSQL SQL login/role or modify current API identities and Terraform root. See [ADR 0098](../adr/0098-isolated-postgres-runtime-managed-identity-candidate.md) and [operator runbook](AZURE_POSTGRES_RUNTIME_UAI_CANDIDATE.md). The existing `administrator_password=var.postgres_password` state problem under #128/#18 remains OPEN.
