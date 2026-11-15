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

The registry starts empty. A blank dashboard is expected. API `POST /api/v1/stamps/issue` deliberately returns 503 until conformant issuance and verification are implemented.

To remove ephemeral developer data:
```sh
docker compose -f docker/compose.yml down -v
```

The Compose stack is for functional testing of **this baseline**, not legal WORM storage, qualified clock synchronization, HSMs, TLS security or AgID/CAB approval. The registry currently stores DER bytes in PostgreSQL. An independent immutability adapter, signed manifests, legal validation and audit/event hardening are mandatory before production.

The PWA is served via HTTP on localhost (secure context exception); deploy with HTTPS/TLS and locked-down IdP in production.
