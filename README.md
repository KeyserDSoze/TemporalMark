# TemporalMark

Multi-tenant timestamp evidence platform: **ASP.NET Core 10 + DDD, PostgreSQL, React/TypeScript, PWA (Italian/English, light/dark), Keycloak local OIDC, xUnit and Playwright**.

> **NOT QUALIFIED:** the project is a pre-qualification foundation. It cannot issue legal qualified timestamps, is not a qualified trust service provider, and must not be represented as such until the legal entity AND specific service are approved and listed in the Trusted List.

## Current features
- Validated OIDC/JWT and **database-verified tenant admin** identity, no client-selected tenant.
- Database-scoped audit trail for prepared evidence ZIP/receipt downloads and tenant-admin audit history (NOT WORM or independently sealed).
- Tenant-scoped registry summary and pagination in UTC; ZIP export includes `manifest.json` + original `.tsr` bytes (limit: 10,000 records per request).
- Domain invariants for UTC periods and retaining at least one active tenant administrator; PostgreSQL trigger as defence in depth.
- Optional external RFC 3161 provider connector accepts only SHA-256 imprint and returns a stored DER receipt marked **Unverified**; HTTP 503 when no external provider configured. This is not own QTSP issuance and not yet historic Trusted List validation.
- Responsive administration UI with Italian/English translations, theme toggle and PWA service worker setup.
- Local Compose bootstrap for PostgreSQL, Keycloak, .NET API and Nginx-hosted UI.

## Run locally

```bash
docker compose -f docker/compose.yml up --build -d
# Open http://localhost:3000
```
Developer-only login: `demo-admin` / `local-dev-only`. See [Docker guide](docker/README.md) for exact endpoints. **Never reuse local passwords or development identity settings in production.**

## Repository layout

```text
.github/workflows/    CI and release workflows
adr/                  architecture decisions
docs/                 compliance and audit gap register
docker/               reproducible local functional stack
infra/azure/          Terraform reference
scripts/              on-prem bootstrap and database schema
src/backend/
  applications/       ASP.NET Core HTTP boundary
  business/           use cases and interfaces
  domains/            DDD entities and invariants
  infrastructures/    PostgreSQL / external adapters
src/frontend/         React + TypeScript + Tailwind + shadcn/ui conventions
tests/backend/        xUnit
tests/frontend/       Playwright
```

## Run tests
```bash
dotnet test tests/backend/TemporalMark.Domain.Tests/TemporalMark.Domain.Tests.csproj
dotnet test tests/backend/TemporalMark.Business.Tests/TemporalMark.Business.Tests.csproj
cd src/frontend && npm install && npm run build
cd ../../tests/frontend && npm install && npx playwright install chromium && npm test
```

## API surface (current)
- `GET /healthz` — readiness of API process (does not assert DB or legal readiness).
- `GET /api/v1/me` — current authorized tenant; OIDC required.
- `GET /api/v1/stamps/summary?fromUtc=...&toUtcExclusive=...`
- `GET /api/v1/stamps?fromUtc=...&toUtcExclusive=...&offset=0&limit=50`
- `GET /api/v1/audit?fromUtc=...&toUtcExclusive=...&offset=0&limit=25` — recent tenant-scoped access audit (maximum 200/page), **not legally tamper-proof**.
- `GET /api/v1/stamps/{id}/receipt` — authenticated, tenant-protected raw RFC 3161 DER `.tsr` download.
- `GET /api/v1/stamps/export?fromUtc=...&toUtcExclusive=...`
- `POST /api/v1/stamps/issue` — admin-only, JSON `{"digestBase64":"..."}` (32-byte SHA-256 Base64), delegates to server-configured HTTPS RFC 3161 TSA; returns 503 if absent and stores receipts as **Unverified**, NEVER qualified by default.

UTC filters are inclusive at the start, exclusive at the end. Exports are bounded to 10,000 entries and are **not yet legal/audit-ready** because the WORM manifest, complete RFC 3161 validation and trust-list evidence are unimplemented.

## Architecture and compliance
Read [Architecture decisions](adr/0001-architecture-and-deployments.md), [compliance gap register](docs/COMPLIANCE.md), [roadmap](docs/ROADMAP.md) and [threat model](docs/THREAT_MODEL.md). Relevant primary law includes eIDAS 910/2014 as amended, the timestamp-specific EU 2025/1929, and AgID/CAB procedures.

**External TSA config (optional):** set `TimestampProvider__Url` to an explicitly approved HTTPS RFC3161 endpoint and `TimestampProvider__Id` to its controlled provider identifier. For local Compose: `TIMESTAMP_PROVIDER_URL` and `TIMESTAMP_PROVIDER_ID` in your environment. The application parses and checks token signature/imprint/nonce; it does not yet check historic Trusted List status or revocation, so receipts remain *Unverified* and no qualified claim is made. Do not configure production until WORM, full verifier and audit controls are completed.

**Retention:** indefinite retention is the initial business intent, not a verified GDPR retention policy or proof of immutable storage. Future work includes GDPR assessment, WORM evidence and real offline verification.

**Branch convention:** changes are made directly on `main`; automated tests and reviews are strongly recommended before protected production rollout.

## Audit MVP (#21)
When the tenant administrator prepares an export or an individual TSR download, the API persists an audit event **before** returning bytes; write failures prevent the download. History is visible via `GET /api/v1/audit` and in the PWA. `Prepared` means the response was ready, **not** that it reached the client. This pilot table has an update/delete guard, but DB owners can bypass it: it is not independent WORM, tamper-evident or legally qualified audit storage. See [ADR 0005](adr/0005-tenant-audit-mvp.md) and [issue #17](https://github.com/KeyserDSoze/TemporalMark/issues/17) for further work. Existing local databases can be upgraded **without wiping volumes** via `docker compose -f docker/compose.yml run --rm migrate` and regular `up`. Versioned migrations and controlled bootstrap instructions: [database migrations](docs/DATABASE_MIGRATIONS.md) and [ADR 0006](adr/0006-tenant-bootstrap-and-admin-integrity.md). A production migration job, IdP-verified enrollment and fully sealed audit remain outstanding.

## Controlled first-administrator provisioning (#24)
A standalone .NET 10 provisioning command validates signed tokens for two different OIDC identities (platform provisioner + initial tenant admin) against an issuer-pinned JWKS, then creates organization/admin and a one-use token-hash audit record atomically. It has **no public HTTP endpoint** and uses a dedicated database role; normal API credentials cannot insert memberships. See [operator runbook](docs/OPERATOR_PROVISIONING.md) and [ADR 0007](adr/0007-oidc-operator-provisioning.md). Immediate IdP revocation, approval workflow and IdP claim setup remain #23/#14.

Live Keycloak enrollment status checks (#26): the standalone provisioning CLI now requires a confidential Keycloak RFC7662 introspection client and checks both signed access tokens immediately before writing to PostgreSQL. Disabled account tokens, inactive status, identity mismatch or IdP outage fail closed. See [ADR 0008](adr/0008-live-keycloak-introspection.md). This is **not** complete real-time directory-role validation, MFA/approval or Entra production compatibility.

Enrollment now uses a three-stage non-HTTP **request → independent approver → complete** pilot gate (PostgreSQL V006/V007). Distinct OIDC subjects and database roles are enforced; a five-minute approval is atomically consumed and recorded with the created tenant. This does **not** prove certified four-eyes authorization, MFA, WORM audit or account current-role status. See [ADR 0009](adr/0009-independent-approval-gate.md) and the updated [runbook](docs/OPERATOR_PROVISIONING.md).

The pilot CLI also requires an independently authenticated **current Keycloak account and effective-role directory check** for all three enrollment participants, beyond signed JWT and RFC 7662 introspection; see [ADR 0010](adr/0010-keycloak-current-directory-check.md) and [operator guide](docs/OPERATOR_PROVISIONING.md). It does not demonstrate MFA, real independent consent, Entra compatibility or QTSP qualification.

Approver access tokens now pass an additional **signed OIDC ACR + `auth_time` freshness policy** (ADR 0011). The disposable CI password-grant realm is explicitly exempt only for its single hardcoded demo identity; **it does not test MFA**. Real configured Keycloak browser step-up and independently verified consent remain open in #31.

V008 records approval authentication provenance explicitly (`OIDC_ACR_ASSERTED`, local `DISPOSABLE_PASSWORD_ONLY`, historical `LEGACY_UNVERIFIED`), and removes the restricted SQL role's legacy provenance-free approval path. Neither a signed ACR claim nor the local test is proof of MFA. See [ADR 0012](adr/0012-approval-assurance-provenance.md); genuine MFA and independent human signoff are still open under #31.

The disposable integration stack also tests a separate Keycloak browser **password + real OTP** step-up through OAuth Code + PKCE, a subsequent login (not OTP enrollment), signed JWKS ACR checks and the strict .NET approval authentication policy. See [ADR 0013](adr/0013-disposable-keycloak-real-otp-pkce.md). The automated fixture does **not** demonstrate actual independent human consent or certified MFA hardware/device custody; #31 remains open.

A reviewer-only `review` CLI command now reads the original unapproved request from PostgreSQL V009, producing a canonical SHA-256 over scope and expiry; `approve` requires that digest instead of copied operator fields. This improves scope accuracy but is **not a human signature or witnessed consent** (issue #35). See [ADR 0014](adr/0014-db-backed-approval-review.md).

The isolated provisioning CLI now has an explicit, one-time **`reject`** action for a reviewed pending organization. Versioned PostgreSQL V010 makes rejection terminal and exclusive with approval, tracks a bounded reason and reviewer token fingerprint, and prevents proof reuse across both decisions. This is a pilot audit, **not an independently signed human approval or WORM evidence**. See [ADR 0015](adr/0015-terminal-rejection-and-token-proof-replay.md); #35 remains open.

The pilot reviewer CLI supports `challenge`, which issues an **unconsumable, unsigned, server-generated decision challenge** tied to original request scope (PostgreSQL V012). It does **not** approve/reject or prove WebAuthn possession. See [ADR 0016](adr/0016-server-issued-reviewer-challenge.md) and open #38.
