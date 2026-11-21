#!/usr/bin/env python3
"""#136 / ADR 0102: live, disposable loopback Kestrel and pinned Nginx HTTP
checks for a strict 4096-byte pre-auth POST /api/v1/stamps/search body budget.
Run only with explicit CI gate; never use external network URLs or real tokens.
Logs and raw 413 bodies never printed, even on a failing assertion.
"""
import json
import os
import subprocess
import urllib.error
import urllib.request

API = "http://127.0.0.1:8080"
WEB = "http://127.0.0.1:3000"
PATH = "/api/v1/stamps/search"
LIMIT = 4096
COMPOSE = ["docker", "compose", "-f", "docker/compose.yml"]
CANARIES = (
    "CI_SEARCH_BODY_QUERY_NOT_PRIVATE_136",
    "CI_SEARCH_BODY_FAKE_BEARER_136",
    "CI_SEARCH_BODY_FAKE_AGENT_136",
    "CI_SEARCH_BODY_FAKE_REFERRER_136",
    "F" * 64,
    "CI_SEARCH_BODY_PAD_SECRET_136",
)


def probe(base, path, method="GET", payload=None, fake_auth=True):
    headers = {
        "User-Agent": CANARIES[2],
        "Referer": "http://localhost/" + CANARIES[3],
    }
    if fake_auth:
        headers["Authorization"] = "Bearer " + CANARIES[1]
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(
        base + path, method=method, data=payload, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as result:
            return result.status, dict(result.headers), result.read(8192)
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read(8192)


def assert_code(label, result, expected):
    code, headers, body = result
    if code != expected:
        raise AssertionError(
            f"{label}: got HTTP {code}, expected {expected}, body withheld")
    if expected == 413:
        # Never allow a reflected searched SHA-256, inferred match/list,
        # fake bearer, tenant selector or raw request data in an error.
        if any(s.encode() in body for s in CANARIES):
            raise AssertionError(f"{label}: confidential canary reflected in 413")
        if any(term in body for term in (b"hasMore", b"tenantId",
                                         b"organizationId", b"matches")):
            raise AssertionError(f"{label}: 413 leaks tenant/match metadata")
    return headers


def container_logs(service):
    proc = subprocess.run(
        COMPOSE + ["logs", "--no-color", service],
        check=False, text=True, capture_output=True, timeout=40)
    if proc.returncode != 0:
        raise AssertionError("Unable to inspect CI container log output")
    return proc.stdout + proc.stderr


def main():
    if os.environ.get("TEMPORALMARK_CI_SEARCH_BODY_BUDGET") != "1":
        raise AssertionError("Explicit disposable CI search-body gate required")
    small = json.dumps({
        "digestSha256Hex": CANARIES[4],
        "fromUtc": "2026-11-01T00:00:00Z",
        "toUtcExclusive": "2026-11-02T00:00:00Z",
        "offset": 0,
        "limit": 50,
        "padding": CANARIES[5],
    }, separators=(",", ":")).encode("utf-8")
    if len(small) >= LIMIT:
        raise AssertionError("Invalid CI search-body fixture size")
    at_limit = small + b" " * (LIMIT - len(small))
    over_limit = at_limit + b" "
    assert len(at_limit) == LIMIT
    assert len(over_limit) == LIMIT + 1
    query = PATH + "?canary=" + CANARIES[0]

    for name, host in (("direct Kestrel", API), ("pinned Nginx", WEB)):
        assert_code(name + " 4096", probe(host, query, "POST", at_limit), 401)
        headers = assert_code(name + " 4097",
                              probe(host, query, "POST", over_limit), 413)
        if name == "direct Kestrel":
            if "no-store" not in headers.get("Cache-Control", "").lower():
                raise AssertionError("Kestrel 413 lacks privacy no-store")
            # Direct access can bypass Nginx. ASP.NET Core routing normally
            # treats path casing as equivalent; bound this path as well.
            assert_code("direct Kestrel case variant",
                        probe(host, "/API/V1/STAMPS/SEARCH", "POST", over_limit), 413)

        # Do not break other endpoints: JWT authentication should still
        # return 401 instead of imposing this search-only 4KiB restriction.
        assert_code(name + " other POST unaffected",
                    probe(host, "/api/v1/stamps/issue", "POST", over_limit), 401)

    assert_code("Kestrel health", probe(API, "/healthz", fake_auth=False), 200)
    assert_code("Nginx health", probe(WEB, "/healthz", fake_auth=False), 200)

    # Both Nginx 413 error logs and ASP.NET default request logs could echo
    # hostile query, Authorization or JSON contents. Test the ENTIRE actual
    # disposable web/API container stdout+stderr, never print raw logs.
    for service in ("web", "api"):
        logs = container_logs(service)
        if any(sentinel in logs for sentinel in CANARIES):
            raise AssertionError(
                "Search 413 path leaked request canary in CI container logs")
    lines = [line for line in container_logs("web").splitlines()
             if "tm_access status=" in line]
    if not any("status=413 method=POST duration=" in line for line in lines):
        raise AssertionError("Missing real Nginx 413 minimal-access event")
    for line in lines:
        fields = line.split("tm_access ", 1)[-1].split()
        if len(fields) != 3 or not fields[0].startswith("status=") or \
                not fields[1].startswith("method=") or \
                not fields[2].startswith("duration="):
            raise AssertionError("Unexpected sensitive Nginx access log fields")

    print("PASS: direct Kestrel and pinned Nginx search POST body 4096=>401, "
          "4097=>413; no raw imprint/query/bearer in 413 or web/API logs; "
          "other POST and health unaffected")


if __name__ == "__main__":
    main()
