# TemporalMark

Multi-tenant timestamp evidence platform: **ASP.NET Core 10 + DDD, PostgreSQL, React/TypeScript, PWA (Italian/English, light/dark), Keycloak local OIDC, xUnit and Playwright**.

> **NOT QUALIFIED:** the project is a pre-qualification foundation. It cannot issue legal qualified timestamps, is not a qualified trust service provider, and must not be represented as such until the legal entity AND specific service are approved and listed in the Trusted List.

> **V015 SECURITY INTERLOCK:** standalone `registrar-intent` issuance is **SUSPENDED**. The original arbitrary-subject SQL function has no EXECUTE grant for the registrar group, and the .NET CLI denies **before reading tokens or connecting to IdP/SQL**. See [ADR 0025](adr/0025-fail-closed-registrar-sql-issuance-interlock.md). Do not regrant or bypass this pending verified signed registration.

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
infra/azure/          Terraform reference (OCI #120, OIDC #122, private ACA #123/#124, private Blob #125)
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
- `POST /api/v1/stamps/search` — authenticated **exact SHA-256 document-imprint** lookup in JSON body `{fromUtc,toUtcExclusive,digestSha256Hex,offset,limit}` (64 ASCII hex characters, 1–50 rows/page, one-row hasMore lookahead, no digest in URL). Query uses server-selected tenant and bounded UTC period, returns metadata only, never raw DER; the IT/EN portal has separate search/pagination controls ([ADR 0081](adr/0081-tenant-document-sha256-imprint-exact-lookup.md), [operator guide](docs/DOCUMENT_IMPRINT_SEARCH.md)). Matching an unverified stored imprint is **NOT signed/qualified timestamp validation or WORM evidence**. A successful authorized lookup now creates a **separate privacy-minimized pilot search audit event** before returning match metadata (V018/#114), but this is **not** independently sealed audit or a legally qualified verification; the scoped shared-primary PostgreSQL quota (V019/#116) now limits valid searches to 12 per actor and 30 per tenant per UTC minute, returning 429/Retry-After without matches; production proxy/body logging, retention/DPIA and edge-abuse governance remain open in #115/#113. See [rate gate runbook](docs/IMPRINT_SEARCH_RATE_LIMITING.md) and the separate [Nginx access-log privacy runbook](docs/NGINX_ACCESS_LOG_PRIVACY.md). The **shared web image** now writes status/method/duration-only Nginx access entries (#117) rather than the inherited combined request-line logs. V020/#118 adds a separately controlled owner-only **manual** deletion of stale search-quota actor IDs, with no automatic cadence or legally approved retention (see [operator runbook](docs/IMPRINT_RATE_COUNTER_CLEANUP.md)). The shared .NET 10 API binary now suppresses normal request-start/routing Information logs and disables HTTP body/header logging (#119; [API log runbook](docs/API_LOG_PRIVACY.md)), while preserving Warning/Error incident diagnostics. **Azure-managed ingress, independent proxies, application/IdP/exception/error logs, scheduled counter cleanup, backup deletion and full GDPR log retention remain unverified** (#115/#113).
- `GET /api/v1/stamps/summary?fromUtc=...&toUtcExclusive=...`
- `GET /api/v1/stamps/daily?fromUtc=...&toUtcExclusive=...` — tenant-admin-only UTC daily totals for **1–31 complete UTC days** (midnight bounds required), zero days included; returns 400 on invalid periods. Same PostgreSQL tenant filter as summary, **counts stored pilot records, not qualified stamps** ([ADR 0079](adr/0079-tenant-utc-daily-dashboard-counts.md), [operator guide](docs/DAILY_DASHBOARD_UTC_COUNTS.md)). The IT/EN dashboard displays the daily chart for valid windows and retains existing total/list/audit/export for longer ranges.
- `GET /api/v1/stamps?fromUtc=...&toUtcExclusive=...&offset=0&limit=50` — tenant-scoped read-only pagination: `offset >= 0`, `1 <= limit <= 200`, order UTC issuance/ID; React IT/EN portal now supports **Previous/Next** through 50-row pages and resets on period/session changes ([ADR 0080](adr/0080-admin-tenant-registry-pagination-and-stale-request-gate.md), [guide](docs/REGISTRY_PAGINATION_UI.md)). Offset pagination is **not** an immutable snapshot or signed evidence-completeness witness.
- `GET /api/v1/audit?fromUtc=...&toUtcExclusive=...&offset=0&limit=25` — recent tenant-scoped access audit (maximum 200/page), **not legally tamper-proof**.
- `GET /api/v1/stamps/{id}/receipt` — authenticated, tenant-protected raw RFC 3161 DER `.tsr` download.
- `GET /api/v1/stamps/export?fromUtc=...&toUtcExclusive=...`
- `POST /api/v1/stamps/issue` — admin-only, JSON `{"digestBase64":"..."}` (**exactly 44 canonical padded standard Base64 characters** encoding one 32-byte SHA-256 digest; no spaces, line breaks, alternate pad bits or Base64URL), rejects noncanonical/oversized inputs with HTTP 400 **before** any TSA request, delegates to server-configured HTTPS RFC 3161 TSA; returns **503** if the TSA is unconfigured/unreachable or responds with upstream **408/429/503/504** (no automatic retry), **502** for an invalid or unexpected TSA response, and stores receipts as **Unverified**, NEVER qualified by default. Canonical encoding is **not** request idempotency or proof of qualified trust; see ADR 0072.

UTC filters are inclusive at the start, exclusive at the end. Tenant-scoped list pages and period ZIP exports fail closed if a stored TSR's SHA-256 digest is inconsistent or an ID is duplicated within the returned batch ([ADR 0074](adr/0074-registry-page-export-integrity-and-unique-ids.md), [operator guide](docs/REGISTRY_INTEGRITY_READ_GATES.md)); this local check is not a signed WORM integrity witness. Synchronous ZIP exports are bounded to **10,000 entries, 1 MiB raw DER per receipt and 64 MiB total raw DER**, with an HTTP 413 request to split the interval on excess ([ADR 0075](adr/0075-synchronous-evidence-zip-byte-budget.md)); these limits apply **before ZIP allocation** but do not bound PostgreSQL row materialization or ZIP output bytes. Exports are **not yet legal/audit-ready** because the WORM manifest, complete RFC 3161 validation and trust-list evidence are unimplemented. To inspect an exported ZIP **offline for local structure and DER/SHA-256 consistency only**, run `python3 tests/integration/verify_period_export.py /path/to/export.zip` ([operator guide](docs/OFFLINE_PERIOD_EXPORT_VERIFIER.md), [ADR 0076](adr/0076-offline-zip-structure-sha256-self-consistency.md)). This does NOT authenticate the unsigned manifest, check an RFC3161/CMS signature or prove qualified service/period completeness.

## Architecture and compliance
Read [Architecture decisions](adr/0001-architecture-and-deployments.md), [compliance gap register](docs/COMPLIANCE.md), [roadmap](docs/ROADMAP.md) and [threat model](docs/THREAT_MODEL.md). Relevant primary law includes eIDAS 910/2014 as amended, the timestamp-specific EU 2025/1929, and AgID/CAB procedures.

**External TSA config (optional):** set `TimestampProvider__Url` to an explicitly approved HTTPS RFC3161 endpoint and `TimestampProvider__Id` to its controlled provider identifier. For local Compose: `TIMESTAMP_PROVIDER_URL` and `TIMESTAMP_PROVIDER_ID` in your environment. The application parses and checks token signature/imprint/nonce; it does not yet check historic Trusted List status or revocation, so receipts remain *Unverified* and no qualified claim is made. Do not configure production until WORM, full verifier and audit controls are completed.

**Retention:** indefinite retention is the initial business intent, not a verified GDPR retention policy or proof of immutable storage. Future work includes GDPR assessment, WORM evidence and real offline verification.

**Branch convention:** changes are made directly on `main`; automated tests and reviews are strongly recommended before protected production rollout.

## Audit MVP (#21)
When the tenant administrator prepares an export or an individual TSR download, the API persists an audit event **before** returning bytes; write failures prevent the download. With V018, every successful authorized document SHA-256 imprint search also appends a **separate metadata-minimized event before returning matches**: only authenticated tenant, actor, action and UTC occurrence (never the queried imprint, match flag, result count or receipt IDs). Search audit write failure prevents the search response. This is a pilot application audit, **not** tamper-evident/WORM protection or a privacy-retention approval. Distributed tenant/principal search rate limiting and body/proxy log redaction governance remain [open #113](https://github.com/KeyserDSoze/TemporalMark/issues/113). History is visible via `GET /api/v1/audit` and in the PWA. `Prepared` means the response was ready, **not** that it reached the client. This pilot table has an update/delete guard, but DB owners can bypass it: it is not independent WORM, tamper-evident or legally qualified audit storage. See [ADR 0005](adr/0005-tenant-audit-mvp.md) and [issue #17](https://github.com/KeyserDSoze/TemporalMark/issues/17) for further work. Existing local databases can be upgraded **without wiping volumes** via `docker compose -f docker/compose.yml run --rm migrate` and regular `up`. Versioned migrations and controlled bootstrap instructions: [database migrations](docs/DATABASE_MIGRATIONS.md) and [ADR 0006](adr/0006-tenant-bootstrap-and-admin-integrity.md). A production migration job, IdP-verified enrollment and fully sealed audit remain outstanding.

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

## WebAuthn relying-party policy groundwork (#40)

A new .NET 10 **validation-only** WebAuthn reviewer RP policy rejects insecure/noncanonical HTTPS origins and requires an explicitly pinned RP hostname exactly matching the trusted origin. It does **not** register credentials, validate signatures or authorize/reject enrollment. See [ADR 0017](adr/0017-pinned-webauthn-rp-origin-policy.md) and [on-prem/Azure security checklist](docs/WEBAUTHN_RP_POLICY.md). Reviewer-held cryptographic consent, verified browser assertions and legacy SQL grant cutover remain #38; no QTSP or WORM status is implied.

## WebAuthn assertion client-data guard (#41)

The standalone .NET business layer also contains a **non-authorizing**, bounded WebAuthn Level 3 `clientDataJSON` preflight that checks exact V012 nonce/base64url, assertion type, pinned origin and top-level context; malicious duplicates, invalid UTF-8 and malformed JSON are denied. This parser is **not wired into any approval/registration endpoint** and does NOT verify an authenticator signature, reviewer-held key, user verification, decision or challenge consumption. See [ADR 0018](adr/0018-webauthn-clientdata-preflight.md) and [reviewer security guide](docs/WEBAUTHN_CLIENT_DATA.md). Production signer, SQL grants and governance remain #38; no legal qualification implied.

## WebAuthn authenticatorData structural guard (#42)

The .NET 10 business layer also has a validation-only `authenticatorData` basic assertion guard: exact RP ID SHA-256, UP+UV flags, BE/BS legality and **untrusted** unsigned big-endian counter extraction; extension/attestation payloads are denied by this first strict profile. It is **not a signature verifier**, never authorizes a decision and has no API or SQL route. See [ADR 0019](adr/0019-webauthn-authenticator-data-preflight.md) and [operator guidance](docs/WEBAUTHN_AUTHENTICATOR_DATA.md). Parent #38 still needs independently enrolled registered keys, signed WebAuthn verification, transactional consumption and revocation of direct reviewer SQL grants. No QTSP/WORM evidence is claimed.

## WebAuthn exact original signed-message transcript (#43)

The isolated .NET 10 business layer can now construct the **untrusted** WebAuthn assertion signing message `authenticatorData || SHA256(clientDataJSON)` from original bytes, after strict client JSON and authenticator-data preflights. This is only preparation for a *future* independently reviewed verifier and does **not** check signatures, authorize/reject a request, consume a challenge, register public keys or confer qualified legal status. See [ADR 0020](adr/0020-webauthn-unsigned-signing-transcript.md) and [operator caution](docs/WEBAUTHN_TRANSCRIPT.md). #38 still requires a maintained WebAuthn verifier, independently approved key registration, explicit human review and removal of direct SQL approval/rejection bypass. #40/#41/#42 were closed with verified four-job CI; #43 stays open until its own exact-head checks pass.

## Reviewer credential registrar groundwork — V013 (#45)

The PostgreSQL foundation now includes an owner-pinned exact HTTPS WebAuthn reviewer RP/issuer policy and an **unconsumable** 48-byte registration nonce, issued only by a separate NOLOGIN registrar group with no seeded members. An intent contains no public key, attestation or active credential and cannot approve or reject organizations. The group and owner inputs are **not** cryptographic proof of an authenticated independent registrar; actual registration/verification and key revocation still require #44 and signed reviewer approval/SQL privilege cutover #38. See [ADR 0021](adr/0021-registrar-only-unconsumable-credential-intent.md) and [on-prem/Azure runbook](docs/WEBAUTHN_REGISTRAR_INTENT.md). Do not infer QTSP/WORM status.

## Independent registrar identity guard (non-authorizing, #47)

The .NET 10 business layer has a dual-principal OIDC preflight for a future WebAuthn registrar ceremony: verifies signed JWT identity with pinned distinct registrar/reviewer audiences and roles, fresh claimed MFA ACR/auth_time, live RFC7662 token status and independent current Keycloak enabled-user/effective-role checks; same-subject witnesses and SQL-original-actor overlap are denied. It is deliberately **not connected** to the CLI, API or V013 registrar SQL issuance. No real registrar login or WebAuthn credential can be approved or registered by this result. See [ADR 0022](adr/0022-registrar-dual-oidc-identity-preflight.md) and [runbook](docs/WEBAUTHN_REGISTRAR_IDENTITY.md). Full signed key registration (#44), real current registrar MFA/SQL integration (#46), signed human decision and old grants cutover (#38), WORM/QTSP (#17/#13) all remain OPEN.

## Registrar real browser MFA integration test — CI only (#48)

A disposable Keycloak test realm now exercises a **separate registrar and reviewer** through actual browser password+OTP and Code+PKCE S256, distinct signed issuer/audiences/roles, and the production .NET verifier+RFC7662+current effective-role gate. A previously valid registrar token must fail after role removal or account disablement; no password-grant or fake MFA exception is used for these tests. The hardcoded disposable loopback test issuer is **not allowed in production by default**. Neither on-prem nor Azure gains an approved registrar service, SQL grant, registered FIDO2 credential or one-time signed decision. See [ADR 0023](adr/0023-disposable-keycloak-registrar-browser-mfa.md) and [CI/security runbook](docs/KEYCLOAK_REGISTRAR_MFA_CI.md); #46/#44/#38 and WORM/QTSP #17/#13 remain OPEN.

## Dedicated two-person registrar intent (no credential registration)

A new **isolated operator CLI** `registrar-intent` can, when separately CAB-configured with a real **HTTPS** Keycloak realm, two strong signed/live/current registrar+reviewer identities, exact approved RP/reviewer scope and a privileged-but-narrow *dedicated* SQL LOGIN, issue the V013 **unconsumable** registration nonce. Unlike the public API or existing provisioning approver, it never accepts caller-specified issuer/RP/signer data or uses a migration-owner DB login. No registrar SQL account/membership is automatically provisioned. A compromised dedicated SQL login can bypass the application gate, requiring operator vault/network segregation; neither token validation nor nonce is WebAuthn attestation or approved human consent. See [ADR 0024](adr/0024-isolated-registrar-sql-intent-workflow.md) and [operator guide](docs/REGISTRAR_SQL_INTENT.md). True WebAuthn credential enrollment (#44), production registrar identity/replay controls (#46), signed reviewer decisions/SQL cutover (#38), and WORM/QTSP (#17/#13) remain OPEN.

## V015 registrar security interlock — issuance suspended

**Important current limitation:** The former `registrar-intent` standalone CLI from #49 is **intentionally disabled** by forward-only V015 and its fail-closed Npgsql adapter, because a stolen dedicated SQL LOGIN could otherwise call V013 directly without signed two-person authorization. This supersedes the earlier description of it as an available issuer. The NOLOGIN registrar SQL role can no longer execute V013; 16 immutable migrations are required. No HTTP API or alternate bypass is provided. A signed one-time FIDO2/WebAuthn registration authorization + atomic SQL release and separately approved/key-custodied registrar remain #50/#44/#46 **OPEN**; human signed tenant decisions #38, WORM #17 and legal/QTSP #13 remain OPEN. See [ADR 0025](adr/0025-fail-closed-registrar-sql-issuance-interlock.md) and [runbook](docs/REGISTRAR_SQL_INTENT.md).

## V016: direct SQL regrants also fail closed

The V015 registrar issuer suspension is reinforced by **V016**: a database trigger rejects legacy registration-intent INSERT operations from nonowner SQL sessions, even if direct function EXECUTE was accidentally granted to a compromised registrar login. The standalone registrar CLI remains suspended; do not reenable it through SQL grants. Current migration count is **16**. Database owners can still alter their schema, and the missing independently authorized FIDO2/WebAuthn registration and one-use signed SQL release remain tracked in #50/#44. See [ADR 0025](adr/0025-fail-closed-registrar-sql-issuance-interlock.md).

## Fido2 WebAuthn attestation candidate verifier — isolated only (#52)

Infrastructure now pins stable maintained `Fido2` **4.3.3** on .NET 10, and an isolated candidate verifier enforces exact original nonce/RP/user-handle/UV/attestation and delegates raw registration cryptographic processing to the library. It **never returns a trusted registered public key**, only hashes and `UNAPPROVED` metadata. The verifier has no API/CLI/SQL integration, registration activation or provenance-MDS trust. The **V015/V016 registrar issuance suspension remains active**; do not use these candidates or the prior arbitrary-subject SQL function as evidence of human registrar consent or signer ownership. See [ADR 0026](adr/0026-fido2-registration-candidate-verifier.md) and [runbook](docs/WEBAUTHN_ATTESTATION_CANDIDATE.md). #44/#50/#46/#38 and WORM/QTSP #17/#13 remain OPEN.
