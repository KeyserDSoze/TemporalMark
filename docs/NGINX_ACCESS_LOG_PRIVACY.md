# Nginx web-container access log minimization — scoped #117

**Pilot security control only. Not full log privacy compliance, qualified TSA evidence, WORM custody or a GDPR/DPIA approval.** [ADR 0084](../adr/0084-minimized-nginx-imprint-search-access-log.md), [parent #115](https://github.com/KeyserDSoze/TemporalMark/issues/115), [#113](https://github.com/KeyserDSoze/TemporalMark/issues/113) and [#17](https://github.com/KeyserDSoze/TemporalMark/issues/17) remain the governing context.

## Controlled part of the stack

The **same built frontend Nginx image** is used by disposable/on-prem Docker Compose and referenced in Azure Container Apps Terraform, assuming the reviewed image digest/artifact is deployed unchanged. `docker/nginx-privacy-logs.conf` is copied into `/etc/nginx/conf.d/00-temporalmark-log-format.conf`, which the pinned Nginx base image includes at `http` context. It is a **static** file, not expanded by envsubst; `$status`, `$request_method` and `$request_time` remain Nginx variables. `docker/nginx.conf.template` selects the named format explicitly for this web server:

```nginx
log_format temporalmark_minimal 'tm_access status=$status method=$request_method duration=$request_time';
```

```nginx
access_log /dev/stdout temporalmark_minimal;
```

The source is split intentionally because `log_format` is allowed in Nginx's **http** context, while `access_log` may be set at **server** scope (see [NGINX reference](https://nginx.org/en/docs/http/ngx_http_log_module.html)). Allowed access fields: fixed marker `tm_access`, numeric HTTP status, method and processing duration. **Neither the full URL/request line nor path, query, request JSON body, SHA-256 imprint, Authorization/Cookie, OIDC subject, tenant identifier, client IP, referrer or user-agent is included.** This intentionally sacrifices route/IP diagnostics in the container access stream. The authenticated #114 audit trail in PostgreSQL remains distinct from this anonymous proxy access telemetry; the #116 PostgreSQL per-tenant/principal limiter is unchanged.

## Scope and genuine test proof

The backend CI source policy `tests/integration/test_nginx_access_privacy.py` enforces the **exact** allowlist, the server override and its installation in the shared frontend image. The mandatory `docker-smoke` job, **after web/API health checks**, executes `tests/integration/nginx-access-privacy.py` against the real pinned running Nginx container on loopback port 3000. The test uses a disposable synthetic path, query, fake Authorization bearer, referrer, user-agent and SHA-256-shaped JSON POST body, checks successful SPA 200 and real proxied anonymous search 401, and reads actual Nginx `docker compose logs web` bytes. It requires access lines containing `tm_access status=200 method=GET duration=` and `tm_access status=401 method=POST duration=`, rejects any extra fields and **rejects canary bytes anywhere in the web-container stdout/stderr captured by the test**, which catches a parallel legacy combined access stream. Captured raw logs are never printed or uploaded by the test.

Reproduce **only on a disposable local CI-compatible stack**, not with customer data or live JWTs:

```sh
docker compose -f docker/compose.yml up -d --build
python3 -m unittest discover -s tests/integration -p 'test_nginx_access_privacy.py' -v
TEMPORALMARK_CI_NGINX_ACCESS_PRIVACY=1 python3 tests/integration/nginx-access-privacy.py
```

The fake bearer is never usable for authentication and the synthetic imprint is not a real customer document fingerprint. Never disable the auth gate for this test.

## Not yet controlled; operator release stop-line

This change only configures the **web container's normal access events**. It **does not** inspect or reconfigure the Azure Container Apps **managed ingress/edge request logging**, any external reverse proxy/WAF/CDN, private API ASP.NET Core request/error traces, Nginx error paths under all conditions, Keycloak logs, third-party agents, or Azure Log Analytics capture/retention. Azure reference Terraform is not a deployed proof; it sets 30-day Log Analytics interactive retention but has no approved privacy-purpose retention, controlled deletion of backup copies or DPIA. Operators can add a second access log or log body/headers; production config and deployed image review, log shipping filters, role-based log access, incident retention and DSR workflows are **release gates**, not guaranteed by this CI test.

Before any production/on-prem/Azure rollout, independently inspect the **effective** Nginx config (`nginx -T`) without pasting secrets, actual public ingress/gateway formats, upstream application error/access logs and sinks; test synthetic query/headers/body against *every deployed* log pipeline and approve privacy/legal retention. Edge/pre-auth DoS rate limiting and multi-primary failover remain in #115; subject IDs in V019 quota SQL tables need independent retention/deletion governance. No WORM or eIDAS QTSP claim; pilot receipts remain `Unverified`, V015/V016 registrar interlocks remain active.
