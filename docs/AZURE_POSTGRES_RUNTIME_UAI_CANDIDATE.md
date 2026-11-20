# Isolated PostgreSQL runtime user-assigned managed identity (UAI) Terraform candidate — #132 / ADR 0098

**PREQUALIFICATION / MOCK PLANS ONLY. DO NOT APPLY IN AZURE. NOT PRODUCTION READY.** This document describes exactly one *new, detached* user-assigned managed identity in `infra/azure/candidates/entra_postgres`, not a migration, SQL principal grant, credential rotation, Azure approval or actual Container Apps identity attachment. See [ADR 0098](../adr/0098-isolated-postgres-runtime-managed-identity-candidate.md), [#132](https://github.com/KeyserDSoze/TemporalMark/issues/132), parent [#128](https://github.com/KeyserDSoze/TemporalMark/issues/128), Azure [#18](https://github.com/KeyserDSoze/TemporalMark/issues/18), [Entra-only server candidate](AZURE_POSTGRES_ENTRA_CANDIDATE.md), [Npgsql data-source candidate](ENTRA_POSTGRES_NPGSQL_CANDIDATE.md) and [Container Apps token supplier candidate](AZURE_CONTAINER_APPS_POSTGRES_IDENTITY_CANDIDATE.md).

## What Terraform models, and deliberately does not do

The *existing*, separate root `infra/azure/candidates/entra_postgres/` previously described only a distinct PostgreSQL 17 Entra-only **new** server, Entra **Group** administrator, and separate `temporalmark_candidate` database; none of them was deployed. It now also declares:

`azurerm_user_assigned_identity.postgres_runtime_candidate`

The identity is located in the externally authorized, already-existing `resource_group_name` and `location` for the pilot, with mandatory explicit `postgres_runtime_identity_name` matching a lowercase, bounded name ending **`-pg-mi-candidate`**. That name must not equal the Entra administrator Group or PostgreSQL server name. It shares the candidate-only tags `environment=disposable-entra-candidate`, `compliance=NOT_QUALIFIED`, `auto_deploy=DENIED` and `prevent_destroy=true`. Any future approved `terraform apply` would **create and retain** a new identity and must have CAB review, remote state custody and planned removal/decommission; there is **no actual apply in this project CI**.

This root **does not** create or update the current application Container App, does not attach the UAI to a running app, does not alter the Azure Key Vault UAI or Blob system identity, does not assign Azure RBAC, does not create an Entra PostgreSQL administrator for the UAI, and does not execute `pgaadauth_create_principal` or any SQL migration/grant. It creates no secret, access token, SQL password, evidence content or PII. These protections are explicitly checked in source tests in addition to the mocked plan.

The current Azure production-reference root `infra/azure/main.tf` **still sets `azurerm_postgresql_flexible_server.registry.administrator_password=var.postgres_password`**. It persists in state and may remain in historical state snapshots and backup copies. This candidate makes **no** change to that risk.

## Non-secret Terraform metadata outputs

The candidate defines three outputs only. Values are **provider-computed and UNKNOWN in a mock plan**; the CI deliberately does not pretend they are valid UUIDs or an attached/app-authorized identity.

| Output name | Azure identity meaning | Future authorized consumer |
|---|---|---|
| `postgres_runtime_identity_resource_id` | Azure Resource Manager ID (`/subscriptions/.../providers/Microsoft.ManagedIdentity/userAssignedIdentities/...`) | Independent change request to attach a UAI to a *separately approved* Azure Container App |
| `postgres_runtime_identity_client_id` | Entra application/client GUID | Supply explicit `client_id` to local Azure Container Apps `IDENTITY_ENDPOINT` request in the detached .NET [#131 candidate](AZURE_CONTAINER_APPS_POSTGRES_IDENTITY_CANDIDATE.md) |
| `postgres_runtime_identity_principal_id` | Entra service principal **object** GUID, different from client ID | Verify Entra directory object and map a **separate least-privilege SQL principal** by an authenticated approved Entra PostgreSQL administrator |

An Azure ARM role assignment is **not** the same thing as PostgreSQL SQL permissions. Neither a created UAI nor its metadata outputs prove that `pgaadauth_create_principal` ran successfully or that any database login can succeed. Identity existence, tenant/issuer match, grants, `CONNECT`, `USAGE`, schema/table/function privileges, failure/rotation behavior and token expiry remain live gates.

## Running offline CI checks

The mandatory workflow uses AzureRM **mock_provider** only, including the original 13 Entra candidate cases plus six additional UAI positive/negative tests. The Terraform job also runs the original 46 Azure root mocked plans, and the backend job executes Python source-policy checks rejecting source credentials, live-module attachment, SQL admin or Azure RBAC. Example local checks **without apply** (these only check syntax and mock plans):

```sh
terraform -chdir=infra/azure/candidates/entra_postgres fmt -check -recursive
terraform -chdir=infra/azure/candidates/entra_postgres init -backend=false
terraform -chdir=infra/azure/candidates/entra_postgres validate
terraform -chdir=infra/azure/candidates/entra_postgres test -no-color -filter=tests/entra_only_candidate.tftest.hcl
python3 -m unittest discover -s tests/integration -p 'test_azure_entra_candidate_source.py' -v
```

The fake identifiers and provider-computed values from tests must never be used as real tenant, identity or resource evidence. No Azure network or management-plane call occurs in these plan-only tests.

## Real Azure adoption — independent approvals required

1. Cloud/security/DB owners approve pilot subscription, tenant, region, existing RG and private topology; validate real Entra Group administrator custody, disaster recovery, state store and **distinct** UAI resource name/client/object IDs against the directory after a separately authorized create. Do not attach to the current API until code and security review.
2. A separate SQL owner authenticates to the **new** Entra-only PostgreSQL candidate via the approved Entra administrator; resolves the intended UAI **service principal object ID**, creates a **non-admin**, least-privilege runtime SQL role using Microsoft documented `pgaadauth_create_principal` procedure, and grants only reviewed database/schema/function/table privileges. **Do not grant `azure_pg_admin`, CREATEDB, CREATEROLE, migration owner or reviewer/registrar roles to the runtime UAI.** Record actual SQL grants, approved identity and correlation to evidence.
3. Independently attach the candidate UAI ARM ID only to a separately reviewed pilot Container App, approve explicitly selected `client_id`, and test real `IDENTITY_ENDPOINT`/header exchange + `NpgsqlDataSourceBuilder.UsePasswordProvider` against private PostgreSQL `SSL Mode=VerifyFull`, DNS, clock, token expiry/refresh/revocation and network failure. Detached #130/#131 components do not wire themselves into any app.
4. Preserve on-prem PostgreSQL/Keycloak and all 20 checksum-locked migrations. Make a separate authorized API/provisioner/registrar/migration-operator plan, matching last-admin invariant, signed two-tenant HTTP 401/403, SQL role separation, backup/restore replay and CAB-managed rollback, before shifting live traffic.
5. Before any production Azure change, protect and rotate **current/historical Terraform state** SQL passwords and previous connection secrets with independent owner and disaster recovery approval. The existing password-auth server must not be switched, replaced, destroyed or locked out by a speculative `terraform apply`.
6. Close #128/#18 only after **live Azure** evidence supports identity, permissions, private TLS, token lifecycle, DDL, audit and credential state remediation, with GDPR/DPIA/WORM/QTSP qualification gates resolved elsewhere. This candidate by itself does not satisfy qualified timestamping or legal preservation.

Official sources: [HashiCorp AzureRM user-assigned identity](https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/user_assigned_identity), [Microsoft Container Apps identities](https://learn.microsoft.com/en-us/azure/container-apps/managed-identity), [Microsoft PostgreSQL Entra role management](https://learn.microsoft.com/en-us/azure/postgresql/security/security-manage-entra-users), [Microsoft PostgreSQL managed identity connections](https://learn.microsoft.com/en-us/azure/postgresql/security/security-connect-with-managed-identity).

## Optional PostgreSQL live SQL privilege preflight candidate (#133 / ADR 0099)

An independent **not wired** Npgsql 10 helper now inspects an **already-authenticated** PostgreSQL session with a parameterized, read-only query, rejecting a runtime principal that is owner/admin, has group membership in `temporalmark_provisioner_group`, `temporalmark_approver_group`, `temporalmark_credential_registrar_group`, privileged built-in groups or optional `azure_pg_admin`, or can mutate core org/member tables/execute bootstrap routines. Real Docker tests use existing **password-based local** runtime, provisioner, approver and owner fixtures, and make no changes to SQL role grants. See [ADR 0099](../adr/0099-detached-readonly-postgres-runtime-privilege-preflight.md) and [runbook](POSTGRES_RUNTIME_PRIVILEGE_PREFLIGHT.md). **This does not make the #132 Entra runtime UAI real or connected**: the managed identity's actual tenant/object ID, future database role grants, Entra SQL login, verified network/TLS, API/CLI role segregation, admin state password removal and CAB are still separate OPEN #128/#18 gates.
