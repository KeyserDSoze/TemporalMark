# API PostgreSQL Entra — explicit Container Apps opt-in and pre-listen SQL privilege gate (#134)

**Scoped prequalification, NOT an authorized Azure deployment or production cutover.** This runbook describes application wiring now present in the .NET 10 API for a *future, independently approved* Entra-only pilot. It does not create a managed identity, make PostgreSQL Entra-only, provision SQL roles, rotate credentials or attest actual Azure connectivity. See [ADR 0100](../adr/0100-explicit-api-entra-postgres-prelisten-privilege-gate.md), [#134](https://github.com/KeyserDSoze/TemporalMark/issues/134), parents [#128](https://github.com/KeyserDSoze/TemporalMark/issues/128) / [#18](https://github.com/KeyserDSoze/TemporalMark/issues/18), [Npgsql token candidate](ENTRA_POSTGRES_NPGSQL_CANDIDATE.md), [ACA token supplier](AZURE_CONTAINER_APPS_POSTGRES_IDENTITY_CANDIDATE.md), [runtime identity Terraform candidate](AZURE_POSTGRES_RUNTIME_UAI_CANDIDATE.md) and [SQL role preflight](POSTGRES_RUNTIME_PRIVILEGE_PREFLIGHT.md).

## Existing default: OSS on-prem and active Azure remain unchanged

When `RegistryPostgres:AuthenticationMode` is **absent**, the API still registers its existing `NpgsqlDataSource.Create(ConnectionStrings:Registry)` and follows the current, independent SQL connection-string credential flow. The explicit literal `Password` selects that same legacy mode. This retains the existing Keycloak/PostgreSQL 17 on-prem development and deployment paths without mandatory Azure dependencies. Any unknown/blank/case-altered mode **fails startup** rather than silently choosing an authentication path. The current Azure Terraform reference does **not** opt in to Entra and **still sets** `azurerm_postgresql_flexible_server.registry.administrator_password = var.postgres_password`; current and historic Terraform state can contain the admin password. The #127 versioned Key Vault API SQL connection-string secret reference does not remove that risk.

## Future, explicitly authorized Container Apps Entra candidate

The API supports only this **literal** opt-in value:

`RegistryPostgres:AuthenticationMode=ContainerAppsEntraCandidate`

It must run with ASP.NET `Production` environment. That environment name is **not** evidence of CAB authorization, SQL grants or a tested cloud production setup; the deployment owner must approve every requirement independently.

| Configuration | Intended source | Constraint |
|---|---|---|
| `RegistryPostgres__AuthenticationMode` | Deployment-approved operator configuration | Exactly `ContainerAppsEntraCandidate` |
| `RegistryPostgres__UserAssignedClientId` | Approved client GUID of a **dedicated PostgreSQL runtime** UAI | Canonical lowercase nonzero GUID, not the Blob system identity or Key Vault identity |
| `RegistryPostgres__ExpectedRuntimeLogin` | Reviewed SQL role map | Exactly matches the explicit connection-string `Username`; no tenant/HTTP-derived role |
| `ConnectionStrings__Registry` | Operator-controlled secret/config reference | Passwordless `Host=<approved>.postgres.database.azure.com;Port=5432;Database=<approved>;Username=<approved-runtime-role>;SSL Mode=VerifyFull;GSS Encryption Mode=Disable` |
| `IDENTITY_ENDPOINT` | **ACA platform-injected process environment only** | Strict HTTP loopback `localhost`/127.0.0.1/::1, explicit port, safe path, no external DNS/IMDS or query |
| `IDENTITY_HEADER` | **ACA platform-injected confidential process environment only** | Required platform header with no controls; never log or check into application settings |

Do not enter actual secret, token, identity header, connection string or customer identifiers in repository files, CI variables, logs or command-line arguments. Above strings are configuration illustrations, **not runnable live credentials**. The root `infra/azure/candidates/entra_postgres` creates a *separate non-applied* UAI metadata candidate (#132); it is **not** attached to the active API and exports only provider-computed IDs, which mock plans cannot verify. Terraform never performs actual SQL role mapping.

### Startup sequence and fail-closed behavior

1. The API reads the opt-in **before DI registration**. Unknown mode is denied immediately; Entra mode is denied outside ASP.NET Production.
2. `ContainerAppsEntraApiRegistryCandidate.Create` validates an independently approved client GUID, exact expected SQL login, canonical Azure PostgreSQL hostname, explicit port/user/database, `SSL Mode=VerifyFull`, GSS disabled and **no Password/Passfile/TLS bypass**, and a strict local ACA identity endpoint/header. It composes the existing Npgsql 10 token provider with the existing ACA local REST client. **Construction makes no HTTP request or PostgreSQL connection**.
3. After `builder.Build()` but **before health endpoint registration, API route mapping or `app.Run()`**, the API sets a 15-second total startup cancellation budget and calls `VerifyAtStartupAsync`. This opens a **real async** Npgsql connection (token request for the fixed `https://ossrdbms-aad.database.windows.net/.default` scope; ACA REST uses `resource=https://ossrdbms-aad.database.windows.net`). Npgsql requires private TLS certificate **VerifyFull** against the approved host.
4. The previously tested `PostgresRuntimePrivilegePreflight.VerifyAsync` executes one **read-only PostgreSQL catalog/ACL SELECT** on that actual connected session, requiring exact `session_user=current_user`, reviewed runtime role membership and necessary SELECT/INSERT privileges; it rejects superuser, built-in/Entra `azure_pg_admin`, provisioner/approver/registrar groups, schema/database CREATE, org/membership mutation and privileged bootstrap EXECUTE. The check is not a DDL or SQL GRANT.
5. If any validation, token, PostgreSQL private connectivity, expiry, TLS, privilege or timeout check fails, the API **aborts before binding an HTTP listener** with one generic error; no inner server/token/hostname details, SQL password fallback, ambient Azure credential or retry. The data source and local HTTP identity client are disposed at stop. A successful one-time preflight **does not prove** that roles cannot drift later or pooled connections are immediately revoked on role/token change.

The API's existing JWT verification, tenant-admin DB checks, private stamp/audit/search endpoints and qualified-issuance denial are unchanged. Migrators, separate provisioner/approver/registrar CLI and reviewer SQL interlocks remain on their existing paths; they are **not** made Entra-aware by this API-only slice.

## Negative tests without Azure credentials or any deployment

GitHub Actions runs RED-first xUnit unit tests in `TemporalMark.Provisioner.Tests` for successful **offline construction** and invalid/missing client ID, connection-string SQL password/passfile, untrusted host, TLS downgrade, wrong expected login, malformed ACA endpoint/header and cancelled startup. The backend mandatory Python policy asserts the selection is actually reachable from `Program.cs`, production-only, platform environment-sourced and pre-listen; the published API executable itself is run with **fake** unknown/dev/unsafe-production settings and must exit without opening an HTTP listener or printing fake credential canaries. Current on-prem Docker health, 20 migration checksums, real PostgreSQL tenant/role tests, full `pg_dump/pg_restore`, signed Keycloak registrar/reviewer browser TOTP/PKCE and tenant A/B HTTP 401/403 all remain mandatory. The Terraform job performs only mock plans and **never** `terraform apply`.

These local CI tests **cannot** prove an actual Entra token/SQL grant/ACA assignment, live private VNet/DNS, Azure-host trust chain, password-state deletion, eventual provider token rotation or multi-region failover.

## Separate approved staging and rollback gates — parent #128 / #18 remain OPEN

Before any real enablement, security/DB/cloud operators must independently verify and approve: Entra tenant, Entra Group administrator custodianship, dedicated UAI **client versus object/principal ID**, Container Apps explicit UAI attachment, **non-admin** PostgreSQL principal in `postgres` via an authorized Entra database administrator, least-privilege SQL grants against the application database and functions, account ownership/default ACLs/role revocation, preflight compatibility, controlled migration-owner and reviewer/registrar identities, private PostgreSQL DNS/TLS and root certificate trust, actual ACA identity endpoint shape, token expiry/re-issuance/pooled session revocation, backup restore and two-tenant regression on a real Azure pilot, break-glass and CAB rollback. Record separate owner sign-offs. If the SQL role is missing, **do not grant admin or disable the preflight to make startup succeed**.

The legacy Azure server/Key Vault reference still uses password authentication and still stores its PostgreSQL bootstrap password in current/historical Terraform state. Production remediation requires separate controlled state access/rotation, historical snapshot review and safe data migration; do not blind-apply an isolated new-server root, destroy a live registry, remove credentials without a rollback plan or equate an Azure plan with production safety.

**NOT_QUALIFIED remains mandatory.** No eIDAS QTSP accreditation, independent signed/WORM evidence custody, UTC(k) qualified TSU, DPIA approval or legally sufficient retention is established by this change.

Authoritative references: [Microsoft Azure Container Apps managed identities](https://learn.microsoft.com/en-us/azure/container-apps/managed-identity), [Microsoft Azure PostgreSQL managed identity SQL principal mapping](https://learn.microsoft.com/en-us/azure/postgresql/security/security-connect-with-managed-identity), [Npgsql asynchronous password provider](https://www.npgsql.org/doc/security.html), [PostgreSQL catalog privilege functions](https://www.postgresql.org/docs/17/functions-info.html).

## Registry/audit table privilege denial at the API Entra startup gate (#141)

Under explicit ContainerAppsEntraCandidate only, the one-time SQL pre-listen check now refuses the application login when effective UPDATE or REFERENCES (table-wide **or any one column**) or DELETE/TRUNCATE/TRIGGER permissions exist on timestamp_registry or tenant_audit_events. Such extra rights must be fixed by approved SQL administrators, never by disabling startup inspection. This is independently exercised using PostgreSQL 17 test-only disposable roles [#141](https://github.com/KeyserDSoze/TemporalMark/issues/141) / [ADR 0106](../adr/0106-postgres-append-only-acl-prelisten.md). Default on-prem Password mode, active Azure Terraform, 20 migrations and production grants remain unchanged. The new checks are not a WORM promise or real Entra UAI staging attestation; #128/#18/#17 remain OPEN. See [preflight runbook](POSTGRES_RUNTIME_PRIVILEGE_PREFLIGHT.md).
