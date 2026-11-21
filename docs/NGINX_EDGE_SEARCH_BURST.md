# Pre-auth document-imprint search burst gate in shared Nginx image (#143 / ADR 0108)

**Status: narrowly tested, development/pilot Nginx-image control only. NOT a global rate limit, audited cloud ingress, approved GDPR policy, qualified timestamp service or legal custody.** See [ADR 0108](../adr/0108-nginx-preauth-imprint-search-peer-burst.md), [open parent #115](https://github.com/KeyserDSoze/TemporalMark/issues/115), [open #113](https://github.com/KeyserDSoze/TemporalMark/issues/113) and [#18](https://github.com/KeyserDSoze/TemporalMark/issues/18).

## Scope and fixed policy

The same `src/frontend/Dockerfile` Nginx image is built for the disposable/on-prem Compose stack and referenced as a **web image** in the Azure Terraform reference. Only the exact lowercase proxied route `/api/v1/stamps/search` has Nginx request-frequency admission; unrelated `/api/` endpoints, `/healthz` and SPA delivery do not. The endpoint remains authenticated by .NET signed OIDC and its current PostgreSQL tenant-admin check when a request reaches the API. The direct API listener **does not use** this Nginx limit. Invalid/unauthenticated requests still return `401` unless their *Nginx TCP peer* exceeds the local burst.

The static `docker/nginx-privacy-logs.conf` is copied unchanged into **Nginx HTTP context** and defines a single 1-MiB per-container rate zone:

```nginx
limit_req_zone $binary_remote_addr zone=tm_search_peer:1m rate=2r/s;
```

The exact search `location` in `docker/nginx.conf.template` independently preserves `client_max_body_size 4k`, `error_log /dev/stderr crit`, the existing privacy-minimized inherited **one** access log and proxy headers. It also enables:

```nginx
limit_req zone=tm_search_peer burst=12 nodelay;
limit_req_status 429;
error_page 429 = @tm_search_edge_denied;
proxy_intercept_errors off;
```

The internal named location emits **generic HTTP 429** with `Retry-After: 1` and `Cache-Control: no-store`. Its error diagnostics below `crit` remain suppressed to avoid printing an attacker-controlled original URI/query. `proxy_intercept_errors off` ensures upstream PostgreSQL 429/Retry-After (12 per actor, 30 per tenant, 60-second PostgreSQL UTC windows) is not rewritten by this **pre-auth** Nginx error handler. The 1-second edge retry is a conservative, stateless hint, **not** the backend's exact server-minute reset time. No tenant ID, JWT, query, SHA256, HTTP body or forwarded header is part of the rate key; the in-memory key is the **directly connected peer's binary network address**, which the client cannot rewrite by sending `X-Forwarded-For`.

## Test evidence and reproduction

Following [ADR 0108](../adr/0108-nginx-preauth-imprint-search-peer-burst.md), the [tests-only `main` b679e85](https://github.com/KeyserDSoze/TemporalMark/commit/b679e8554d990f913cbf4e3b8719aa459ddcce64) and [Actions 44920497866](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44920497866) produced a genuine **RED** in a real pinned Nginx/ASP.NET container: after a valid 401 baseline, 48 concurrent anonymous POST searches with forged/rotating `X-Forwarded-For` yielded **no** pre-auth 429 before configuration changes. Implementation [67510d8](https://github.com/KeyserDSoze/TemporalMark/commit/67510d8f04f39256337908b6db24a2c3bf8a9a26) adds the fixed Nginx HTTP/local route gate and 4 mandatory source-policy assertions.

The mandatory `docker-smoke` integration probe `tests/integration/imprint-search-nginx-edge-limit.py` must run with `TEMPORALMARK_CI_NGINX_EDGE_LIMIT=1` against **only the disposable CI loopback web and API**. It sends fake JWT/64-character SHA-shaped JSON, rotates documentation-only forged forwarded IPs, requires at least one real proxy `429` with no response/search metadata and no canaries in actual Nginx logs, validates the inherited `tm_access status/method/duration` allowlist, verifies direct API and unrelated POST still yield 401 and SPA/health remain 200. Backend source-policy `test_imprint_search_nginx_edge_limit.py` is separately mandatory in CI. The old 4-KiB Kestrel+Nginx 413 test, Nginx privacy probe, real signed Keycloak A/B SQL 429 tests, PostgreSQL 20 migrations and dump/restore remain unchanged.

No successful local synthetic request test is proof of actual Azure Container Apps managed ingress or its end-to-end confidential logging.

## Production limitations and operator stop line

- **Per-instance only**: memory is shared among workers of one Nginx process/container, not among frontend replicas/pods or regions. A container restart resets counters; an attacker can alternate replicas or bypass the web proxy by contacting a separately exposed API. Backend PostgreSQL authenticated quota remains the sole tested *cross-API-replica* tenant/principal admission, provided every replica connects to the same writable primary.
- **Trusted client IP topology is unresolved**: when Nginx is behind an ingress/load balancer, its `$binary_remote_addr` may represent that proxy instead of end users. Unrelated tenants behind the same proxy/NAT can then share a limiter bucket and suffer availability reduction. **Never 'fix' this by trusting arbitrary X-Forwarded-For from the request.** Any real-IP module/trusted proxy allowlist and network segregation require an independently reviewed ADR, deployment topology, authenticated edge and tests.
- The zone transiently stores binary connected-peer addresses and request-rate state; consider personal-data/operational proportionality with privacy counsel, telemetry retention and DPIA review before rollout. Nginx local memory isn't persistent personal-data retention, but external edge and container diagnostics/shipper configuration remain unverified. The access log still contains **only status, method and duration**, not IP/URI/imprint, and suppression of subcritical error events is deliberate.
- Fixed 2r/s, burst 12 are conservative **pilot defaults**, not a traffic SLA, DoS/slowloris shield, global/preauth per-account cap or full DDoS protection. Review service capacity, false positives, retries and availability for large shared-proxy IPs. Source excludes body/content handling changes: independent Kestrel 4096-byte cap stays necessary.
- No `terraform apply`, Azure managed ingress validation, CAB endorsement, signed WORM evidence, privacy-approved actor-retention schedule, JWT subject abuse mitigation, QTSP/eIDAS qualification or actual release authorization is performed. Parents #115/#113/#18/#17/#13/#15 remain OPEN.

Official references: [Nginx limit_req](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html), [Nginx proxy_intercept_errors](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_intercept_errors), [Nginx error_page](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page).
