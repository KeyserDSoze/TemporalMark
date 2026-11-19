# ASP.NET Core API normal request logging privacy — scoped #119

**Technical pilot control only. Not a GDPR DPIA/retention approval, complete log redaction or qualified eIDAS/WORM attestation.** Read [ADR 0086](../adr/0086-api-request-diagnostic-log-minimization.md), [Nginx access privacy](NGINX_ACCESS_LOG_PRIVACY.md), open [#115](https://github.com/KeyserDSoze/TemporalMark/issues/115) and [#113](https://github.com/KeyserDSoze/TemporalMark/issues/113).

## What is intentionally suppressed

The shared .NET 10 API uses **code-owned** logging filters in `src/backend/applications/TemporalMark.Api/Program.cs`, without relying only on operator-modifiable `appsettings.Development.json`:

- `Microsoft.AspNetCore.Hosting.Diagnostics` at **Warning** or higher, so ordinary request-start and request-completion Information events (which can contain paths and queries) are not written to configured `ILogger` providers.
- `Microsoft.AspNetCore.Routing.EndpointMiddleware` and `Microsoft.AspNetCore.Routing.Matching.DfaMatcher` at **Warning** or higher, so informational routing/endpoint names cannot leak caller-supplied URL components via the normal pipeline.
- `Microsoft.AspNetCore.HttpLogging.HttpLoggingMiddleware` and `Microsoft.AspNetCore.HttpLogging.W3CLogger` at **None**, and `AddHttpLogging` options `LoggingFields = HttpLoggingFields.None`, so enabling an HTTP logging provider later does not silently opt into request/response body, query or header fields. `UseHttpLogging` and `UseW3CLogging` remain **disabled**.

These changes do **not** alter authentication/authorization, route matching, responses, browser behavior, PostgreSQL search/quota or #114 append-only tenant audit. The log policy is not itself an audit substitute. Operational Warning/Error entries remain possible; errors can still include request-controlled values from exception messages or third-party instrumentation and need independent review.

Official reference: [ASP.NET Core 10 HTTP logging and selectable fields](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/http-logging/?view=aspnetcore-10.0) and [ASP.NET Core logging categories](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/logging/?view=aspnetcore-10.0).

## CI evidence and local test boundary

The backend CI calls `python3 -m unittest discover -s tests/integration -p 'test_api_diagnostic_privacy.py' -v` to fail when the code-owned filters or opt-out are missing. The disposable Docker smoke runs `TEMPORALMARK_CI_API_LOG_PRIVACY=1 python3 tests/integration/api-diagnostic-privacy.py` **after API, Nginx and Keycloak health**. It exercises the actual pinned API container via loopback `127.0.0.1:8080` with synthetic sensitive path, URL query, referrer, user-agent, fake Authorization bearer and JSON `digestSha256Hex` on anonymous HTTP 404/401. It reads `docker compose logs --no-color api` into process memory and checks neither stdout nor stderr contains any synthetic canary; the program prints **no actual captured log lines**, bearer or body, even on failure.

Use only the disposable/isolated development stack. Never reuse this with a real customer fingerprint, JWT, tenancy data, production URL or deployed Azure logs:

```sh
docker compose -f docker/compose.yml up -d --build
python3 -m unittest discover -s tests/integration -p 'test_api_diagnostic_privacy.py' -v
TEMPORALMARK_CI_API_LOG_PRIVACY=1 python3 tests/integration/api-diagnostic-privacy.py
```

Real signed-Keycloak A/B tenant authentication and HTTP 401/403 isolation, rate gate #116 and search audit #114 remain separately tested. API and frontend images are common between OSS/on-prem and Azure reference Terraform; passing container tests is **not evidence of the deployed managed Azure ingress**.

## What is **not** verified or qualified

This control does **not** prove body/URL redaction for arbitrary `ILogger` calls, exceptions (especially development exception pages), authentication-provider warnings/error traces, trace exporters/OpenTelemetry, request replay or network packet capture, remote proxies/Nginx errors, Keycloak identity logs, Azure Container Apps public managed ingress, Application Insights/Log Analytics, external WAF/CDN, backups, SQL account-subject retention, error-event samples or operational overriding of logging configuration. Production privacy governance must inspect actual deployed effective logging pipeline and all log sinks using synthetic probes under approved change control, then define retention/legal basis, DPIA, backup deletion and role-restricted access. Those remain OPEN under #115/#113/#18; WORM and EU qualification remain #17/#13/#15. TemporalMark pilot records remain `Unverified` and V015/V016 reviewer/registrar constraints remain unchanged.
