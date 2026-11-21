#!/usr/bin/env python3
"""#145 / ADR 0110: actual pinned Nginx early request-line 414 privacy/cache gate.

Only fixed loopback Compose services and synthetic canaries. Never send real
tokens, imprints, customer URLs or use arbitrary user-specified destinations.
Captured container logs and HTTP response bodies MUST NOT be printed.
"""
import http.client
import os
import subprocess
import urllib.error
import urllib.request

WEB_HOST = "127.0.0.1"
WEB_PORT = 3000
COMPOSE = ["docker", "compose", "-f", "docker/compose.yml"]
MARKERS = (
    "CI_EARLY_URI_FAKE_IMPRINT_145",
    "CI_EARLY_URI_FAKE_BEARER_145",
    "CI_EARLY_URI_AGENT_PRIVATE_145",
    "CI_EARLY_URI_REFERRER_PRIVATE_145",
    "A" * 64,
)


def request(method, path, data=None, headers=None):
    connection = http.client.HTTPConnection(WEB_HOST, WEB_PORT, timeout=20)
    try:
        connection.request(method, path, body=data, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read(4096)
    finally:
        connection.close()


def check_status(description, result, code):
    if result[0] != code:
        raise AssertionError(
            f"{description}: expected HTTP {code}, got HTTP {result[0]}; body withheld")


def inspect_logs():
    process = subprocess.run(COMPOSE + ["logs", "--no-color", "web"],
                             capture_output=True, text=True, timeout=40)
    if process.returncode != 0:
        raise AssertionError("Could not inspect web logs in disposable stack")
    return process.stdout + process.stderr


def main():
    if os.environ.get("TEMPORALMARK_CI_NGINX_EARLY_414") != "1":
        raise AssertionError("Explicit disposable local-only 414 fixture required")

    base_path = "/api/v1/stamps/search?digestSha256Hex=" + MARKERS[4]
    query = ("&query=" + MARKERS[0] + "&token=" + MARKERS[1] +
             "&pad=" + "P" * 20000)
    path = base_path + query
    if len(path) <= 16384:
        raise AssertionError("Invalid synthetic 414 request-line fixture")

    response = request("GET", path, headers={
        "User-Agent": MARKERS[2],
        "Referer": "http://localhost/" + MARKERS[3],
        "Authorization": "Bearer " + MARKERS[1],
    })
    check_status("early request-line Nginx rejection", response, 414)
    headers = {k.lower(): v for k, v in response[1].items()}
    if "no-store" not in headers.get("cache-control", "").lower():
        raise AssertionError(
            "Pre-location Nginx 414 lacks explicit Cache-Control no-store")
    if any(marker.encode() in response[2] for marker in MARKERS):
        raise AssertionError("Pre-location 414 echoed a private synthetic canary")
    if any(word in response[2].lower() for word in
           (b"matches", b"hasmore", b"tenantid", b"organizationid")):
        raise AssertionError("Pre-location 414 exposed tenant/match metadata")

    logs = inspect_logs()
    if any(marker in logs for marker in MARKERS):
        raise AssertionError(
            "Nginx 414 request-line parsing leaked synthetic private data into logs")
    access = [line.split("tm_access ", 1)[-1].split()
              for line in logs.splitlines() if "tm_access " in line]
    if not any(len(fields) == 3 and fields[0] == "status=414"
               and fields[1] == "method=GET" for fields in access):
        raise AssertionError("Missing minimal Nginx 414 status access event")
    for fields in access:
        if len(fields) != 3 or not fields[0].startswith("status=") or \
                not fields[1].startswith("method=") or \
                not fields[2].startswith("duration="):
            raise AssertionError("Unexpected Nginx access log field")

    check_status("web health", request("GET", "/healthz"), 200)
    spa = request("GET", "/")
    check_status("web SPA", spa, 200)
    if "no-store" in {k.lower(): v for k, v in spa[1].items()}.get(
            "cache-control", "").lower():
        raise AssertionError("414-only policy unexpectedly disables SPA HTTP caching")
    check_status(
        "ordinary anonymous search", request(
            "POST", "/api/v1/stamps/search",
            data=b'{"digestSha256Hex":"' + b"A" * 64 + b'"}',
            headers={"Content-Type": "application/json"}),
        401)
    print("PASS: Nginx early 414 no-store and no synthetic query/token leakage; "
          "minimal status-only access; unaffected SPA/health/search")


if __name__ == "__main__":
    main()
