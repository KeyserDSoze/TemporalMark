# Local development stack (not legally qualified)

Prerequisites: Docker Engine / Desktop with Compose v2. Run from the repository root:

```sh
docker compose -f docker/compose.yml up --build -d
docker compose -f docker/compose.yml ps
```

- Browser admin console: http://localhost:3000
- Keycloak (development IdP): http://localhost:8081
- ASP.NET Core health check: http://localhost:8080/healthz
- PostgreSQL (bound to localhost): 5432

**Local fixture only:** login `demo-admin` / `local-dev-only`. This credential must never be carried into any non-development environment. Local Keycloak admin login: `local-admin` / `dev-only-change-me`. The demo organization is `11111111-1111-1111-1111-111111111111`.

The registry starts empty. A blank dashboard is expected. API `POST /api/v1/stamps/issue` deliberately returns 503 with no external provider configured. For a development-only RFC3161 interop test, set `TIMESTAMP_PROVIDER_URL` (HTTPS TSA endpoint) and `TIMESTAMP_PROVIDER_ID` before Compose startup. The request contains a SHA-256 digest only; the persisted response is marked `Unverified` and does not establish legal qualification.

To remove ephemeral developer data:
```sh
docker compose -f docker/compose.yml down -v
```

The Compose stack is for functional testing of **this baseline**, not legal WORM storage, qualified clock synchronization, HSMs, TLS security or AgID/CAB approval. The registry currently stores DER bytes in PostgreSQL. An independent immutability adapter, signed manifests, legal validation and audit/event hardening are mandatory before production.

The PWA is served via HTTP on localhost (secure context exception); deploy with HTTPS/TLS and locked-down IdP in production.

## Existing databases and organization bootstrap (#22)

The stack now runs `migrate` before starting the API, tracking versioned SQL migrations with SHA-256 checksums. For existing volumes, run `docker compose -f docker/compose.yml run --rm migrate`; **do not use `down -v` to perform an upgrade**, because it destroys persisted data. Details, restrictions, and operator-only enrollment: [database migrations](../docs/DATABASE_MIGRATIONS.md) and [ADR 0006](../adr/0006-tenant-bootstrap-and-admin-integrity.md). Operator identity verification is still manual and not sufficient for a production tenant onboarding flow.

## Disposable MFA integration fixture

For CI only, `docker/compose.yml` imports `docker/keycloak/temporalmark-mfa-ci-realm.json` alongside the existing local realm. It contains a dedicated demo Keycloak user and browser PKCE client, not connected to production approvals. Conditional Keycloak LoA1 (password) and LoA2 (required OTP) implement an interactive regression test, and the browser automation verifies actual code acceptance after a new session. The file, its demo password and localhost-only HTTP **must never be used in production**, even for an on-prem installation. See [ADR 0013](../adr/0013-disposable-keycloak-real-otp-pkce.md) and #31.
