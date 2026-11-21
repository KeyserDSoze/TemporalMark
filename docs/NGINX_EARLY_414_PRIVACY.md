# Nginx early 414 HTTP response caching and request-line privacy (#145 / ADR 0110)

**Technical pilot/shared web-container control only. Not a complete Azure ingress, audit-custody, qualified timestamp, legal-retention or GDPR/DPIA approval.** See [ADR 0110](../adr/0110-nginx-early-414-cache-and-http-error-privacy.md), [parent #115](https://github.com/KeyserDSoze/TemporalMark/issues/115) and [parent #113](https://github.com/KeyserDSoze/TemporalMark/issues/113).

## Why the existing search location is insufficient for an early 414

A client can place a long, attacker-controlled string in the URL/query rather than in the protected **4KiB search POST body**. Nginx rejects a too-long request line **during parsing**, before choosing `location ~* ^/api/v1/stamps/search$`. The existing search-specific `client_max_body_size 4k`, `error_log /dev/stderr crit` and per-peer burst `limit_req` do not necessarily run for this *pre-location* request. Official [Nginx `large_client_header_buffers` documentation](https://nginx.org/en/docs/http/ngx_http_core_module.html#large_client_header_buffers) explains why the HTTP result is `414 URI Too Long`. [RFC 9110 §15.5.15](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.15) explicitly says 414 responses are **heuristically cacheable** unless overridden. Such error pages are an undesirable cache surface for potentially private request targets.

## Exact portable Nginx configuration

The existing `docker/nginx-privacy-logs.conf` file is installed in **HTTP context** by the **same pinned frontend Docker image** for the disposable/OSS stack and referenced as an image in the Azure reference. It defines a status-scoped map:

```nginx
map $status $tm_early_414_cache_control {
    default "";
    414 "no-store";
}
```

The shared `docker/nginx.conf.template` adds one **server-scope** conditional response header:

```nginx
add_header Cache-Control $tm_early_414_cache_control always;
```

Only status **414** receives `Cache-Control: no-store` from this map. Empty variables result in no added header for other status codes, keeping normal PWA/SPA caching, existing upstream cache headers and independent search `413` and local proxy `429` intact. The existing local Nginx 429 internal handler still explicitly sets its own `Cache-Control: no-store` and `Retry-After: 1`; PostgreSQL SQL-quota 429 with its own reset remains passed through via `proxy_intercept_errors off`. The existing `tm_access status/method/duration` access stream is unchanged.

**No new global `error_log crit` was added.** The initial ADR risk assessment considered that a parser-time error might log private URI text and proposed suppressing the HTTP-scope error logger. Genuine pinned Docker RED evidence actually recorded only `tm_access status=414 method=- duration=0.000` and **no synthetic private canary in web stdout/stderr** and **no error-level web log lines** for this exact fixture. The verified defect was missing no-store, *not a proven existing log leak*. ADR 0110 was refined and committed **before source** to preserve unrelated HTTP error diagnostics instead of introducing broad `crit` suppression. Location-scoped `error_log /dev/stderr crit` for the sensitive search POST remains. Log privacy is **not** established for every malformed header, other Nginx error path or cloud ingress.

## TDD, live integration and reproducibility

[Accepted ADR 0110](../adr/0110-nginx-early-414-cache-and-http-error-privacy.md) [`main d55f182`](https://github.com/KeyserDSoze/TemporalMark/commit/d55f1822573d211d14933469968b3a36c5bdde38) preceded [test-only `main 5288111`](https://github.com/KeyserDSoze/TemporalMark/commit/528811126bc629f1038e0280fd7cb0a33c725c2e). In [Actions 44925916344](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44925916344), backend/frontend/Terraform, actual Nginx/Keycloak/PostgreSQL startup and the existing #117/#136/#119 privacy probes passed; the **new live Nginx RED** failed exactly with `Pre-location Nginx 414 lacks explicit Cache-Control no-store` on a synthetic >16KiB request-target. A 414 access log can have `method=-` because the parser has not extracted a valid method before emitting the response: the test now allows this while still enforcing the **same three-field format**.

Following RED, the smallest [`main 7af6550`](https://github.com/KeyserDSoze/TemporalMark/commit/7af65503764a8e92d78992c835465e2aa93b1103) adds the 414-only map, server header, corrected parser-time log assertion and three mandatory Python source-policy tests. Real Docker fixture `tests/integration/nginx-early-414-privacy.py` is wired into `docker-smoke` **before** #143 burst. It is gated by `TEMPORALMARK_CI_NGINX_EARLY_414=1`, fixed to loopback Nginx and uses only synthetic fake token/query/64-byte SHA-shaped data. It never prints raw URLs, request bodies, container logs or confidential values. It requires actual **414** plus no-store, no canary in response or any web container log, minimal 414 status event, unchanged SPA/health 200, unaffected anonymous small search 401 and no forced no-store for SPA content.

Reproduce only with a disposable Docker Compose stack:
```sh
docker compose -f docker/compose.yml up -d --build
python3 -m unittest discover -s tests/integration -p 'test_nginx_early_414_privacy.py' -v
TEMPORALMARK_CI_NGINX_EARLY_414=1 python3 tests/integration/nginx-early-414-privacy.py
```

The exact docs-inclusive GitHub Actions final SHA, 4 core jobs, PostgreSQL 20 migrations, restore and Keycloak MFA/tenant A/B proof remain the release gate for closing #145. Source-only policy cannot establish live HTTP semantics.

## Unresolved operational and legal stop lines

The Nginx source map and Docker test **cannot verify** Azure Container Apps managed ingress, TLS termination/gateway/CDN/WAF early 414 handling, load-balancer diagnostics, alternate HTTP versions, other bad-header errors, Nginx operator overrides, true client IP mapping, multireplica limiter distribution or log-shipping retention. No new access log IP/header/token fields or permanent identity storage are created. Never infer GDPR retention compliance, a verified WORM audit/evidence chain, qualified electronic timestamps, QTSP status, live CAB approval or commercial readiness. Keep #115/#113/#18/#17/#13/#15 OPEN. If a production operator needs request-level error diagnostics, independently design privacy-preserving structured telemetry instead of blindly logging raw URLs or suppressing all critical evidence.
