# Shared PostgreSQL document-imprint search admission — scoped pilot #116

**Not qualified timestamping, WORM audit or a GDPR retention policy.** See [ADR 0083](../adr/0083-postgres-atomic-imprint-search-rate-admission.md) and open [parent #115](https://github.com/KeyserDSoze/TemporalMark/issues/115), [#113](https://github.com/KeyserDSoze/TemporalMark/issues/113) and [#17](https://github.com/KeyserDSoze/TemporalMark/issues/17).

## What the gate actually does

Following signed-JWT validation and a fresh active PostgreSQL `tenant_admin` membership check, `POST /api/v1/stamps/search` validates the UTC period, exact 64-character document SHA-256 hex and bounded pagination. It then calls the shared PostgreSQL 17 primary to consume **two atomic fixed-window quotas** in one SQL transaction:

| Scope | Limit | Database time window |
|---|---:|---|
| One authenticated OIDC `sub` within one organization | 12 successful admissions | 60 seconds, UTC epoch aligned |
| All subjects within the same authenticated tenant | 30 successful admissions | Same 60-second window |

These are conservative **pilot constants**, not service-level policy promises. Denied attempts do not increment counters. A denied request returns HTTP `429`, an integer `Retry-After` of 1–60 seconds, `Cache-Control: no-store`, and **no match/list/hasMore/document imprint**. A malformed imprint still receives 400 before quota; unauthorized role/tenant access receives 401/403. This is not a pre-auth network/edge traffic limiter.

Admission precedes the SQL document-imprint registry read and existing independently scoped #114 audit event. Audit must still persist before any successful search metadata is returned; audit outage still fails closed with HTTP 500. An unavailable/corrupted quota database also fails closed, without local allow-list. These events must never be interpreted as legally sealed custody or proof of HTTP delivery.

## Deployment and migration

- Run **V019** via `scripts/apply-migrations.sh` using the separate migration-owner credentials before deploying the new API binary. Earlier V001–V018 must be checksum-verified unchanged. The normal local `docker compose -f docker/compose.yml run --rm migrate` handles a persistent development volume without deleting data. Production Azure and on-prem must execute the same controlled migration job, backup/change approval and restore test.
- All active API replicas must point at **one writable PostgreSQL primary**. This single-primary invariant is essential: independent region/cluster primaries, edge caches, per-process counters and stale read replicas do not jointly enforce the budget. PostgreSQL transaction-scoped advisory locks serialize each tenant across threads/processes, and the same SQL function updates tenant and principal quotas atomically.
- The SQL `SECURITY DEFINER` function `public.consume_imprint_search_rate(uuid,text)` is callable only by the runtime group. Its two counter tables are not directly readable or writable by that group; migration/schema owners remain privileged. The function uses `pg_catalog,pg_temp` search path and qualified table names. If permission, primary database or clock integrity fails, deny traffic and investigate; do not skip or bypass the limiter.
- Monitor non-sensitive aggregate 429 rates and primary-DB availability under approved telemetry, **never** raw searched SHA-256, bearer, HTTP JSON body or the requester’s credential. Set no reverse-proxy body recording. Production ingress/proxy log validation and independent DPIA review are still required by #115. A **scoped web-Nginx container access-only format** strips request URL/headers/body and IP from its own normal access events (#117; [runbook](NGINX_ACCESS_LOG_PRIVACY.md)), but Azure-managed ingress, external proxies, ASP.NET Core/error logs and production telemetry pipelines remain unverified.
- Rate tables store authenticated OIDC **subject IDs**, tenant IDs, last window and count; these are personal/behavioral metadata. The normal V019 admission function opportunistically deletes up to 32 principals and 16 tenants whose state is over 3 minutes old, **only when another request invokes it**. New forward-only **V020/#118** additionally provides an **owner-only, bounded, manually invoked cleanup** for inactive principals and tenants even without traffic, preserving active counters and returning aggregate deletion counts only (see [owner runbook](IMPRINT_RATE_COUNTER_CLEANUP.md), [ADR 0085](../adr/0085-bounded-owner-imprint-quota-cleanup.md)). **No automatic scheduler, guaranteed idle-row TTL, privacy-approved cadence, backup erasure, DPIA/legal policy or production maintenance verification exists yet**. Those remain open #115/#113; do not deploy as a privacy-complete service.
- No new Azure-only dependencies or secret requirements. Azure managed PostgreSQL and OSS on-prem PostgreSQL must apply the same constraints. Multi-primary, network-level DoS, reverse proxy/bodies, signed audit custody, real QTSP/CAB approval and account/MFA assurance remain separate release gates.

## Live CI verification

The disposable Docker CI test uses real PostgreSQL 17 / signed Keycloak two-tenant A/B HTTP (not a mock). Unit tests cover bad scope/decisions and strict request preflight. PostgreSQL tests exercise two scopes and tenants, **72 parallel SQL sessions** against one tenant, one-minute expiry via owner-controlled *disposable-only* rows, future/rolled-back clock denial and restricted-role direct SELECT denial. Signed-Keycloak HTTP tests exhaust tenant A actor allowance, require `429` and integer `Retry-After`, prohibit data leakage, check forged org selectors cannot bypass, validate 400 even after exhaustion and confirm tenant B remains unaffected. Existing #114 real audit-write-denial probe must still return 500 with no result. No tests use or modify production credentials or live tenant data.

Close only #116 once the exact final documentation-inclusive `main` SHA has independently verified backend/frontend/docker-smoke/terraform all successful, with actual test logs. Keep #115/#113 OPEN for deployment, ingress and privacy governance, and #17/#15/#13 for immutable/qualified/legal requirements.
