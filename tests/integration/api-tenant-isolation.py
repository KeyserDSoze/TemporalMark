#!/usr/bin/env python3
"""CI ONLY: real Keycloak signed JWT, real compiled API and PostgreSQL tenant canaries.

No mock server/membership, no JWT/password/authorization-code output or artifacts.
This script is forbidden against live tenants and requires a disposable Compose stack.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

API = "http://127.0.0.1:8080"
IDP = "http://127.0.0.1:8081"
ISSUER = "http://localhost:8081/realms/temporalmark"
CLIENT = "temporalmark-local-provisioning-tests"
BAD_AUDIENCE_CLIENT = "temporalmark-isolation-no-api-audience-ci"
EXPIRING_CLIENT = "temporalmark-isolation-short-token-ci"
ORG_A = "11111111-1111-1111-1111-111111111111"
ORG_B = "22222222-2222-2222-2222-222222222222"
SUB_A = "00000000-0000-0000-0000-000000000001"
SUB_B = "00000000-0000-0000-0000-000000000082"
SUB_DISABLED = "00000000-0000-0000-0000-000000000083"
STAMP_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaa82"
STAMP_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbb82"
AUDIT_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaab82"
AUDIT_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbb82"
FROM = "2020-01-01T00:00:00Z"
TO = "2099-01-01T00:00:00Z"
DER_A = bytes.fromhex("3003020101")
DER_B = bytes.fromhex("3003020102")
DIGEST_A = bytes([0xA1] * 32)
DIGEST_B = bytes([0xB2] * 32)


def checked_http(url: str, method="GET", token=None, payload=None, headers=None):
    # Never include a bearer, password or OIDC token URL in assertion messages.
    sent_headers = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        sent_headers["Content-Type"] = "application/json"
    if token is not None:
        sent_headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, method=method, data=data, headers=sent_headers)
    try:
        with urllib.request.urlopen(req, timeout=35) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


def must_status(label: str, response, expected: int):
    status, headers, data = response
    if status != expected:
        raise AssertionError(f"{label}: HTTP {status}, expected {expected} (response body withheld)")
    return headers, data


def jwt_claims_untrusted(token: str) -> dict:
    # Only for fixture sanity/expiration; .NET API independently verifies the
    # real Keycloak signature, issuer, expiration, and audience over HTTP.
    segments = token.split(".")
    if len(segments) != 3:
        raise AssertionError("Keycloak fixture failed to mint a JWT")
    return json.loads(base64.urlsafe_b64decode(segments[1] + "=" * (-len(segments[1]) % 4)))


def keycloak_token(user: str, password: str, client_id=CLIENT, realm="temporalmark") -> str:
    endpoint = f"{IDP}/realms/{realm}/protocol/openid-connect/token"
    parameters = urllib.parse.urlencode({
        "client_id": client_id, "grant_type": "password",
        "username": user, "password": password, "scope": "openid"
    }).encode()
    request = urllib.request.Request(endpoint, data=parameters, method="POST",
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        # Deliberately do not print HTTP error body, credentials or token.
        raise AssertionError(f"Missing/invalid disposable Keycloak principal or client: {user}, HTTP {error.code}") from None
    token = result.get("access_token")
    if not isinstance(token, str):
        raise AssertionError(f"No signed access JWT for disposable principal {user}")
    return token


def api(path: str, token=None, method="GET", payload=None, headers=None):
    return checked_http(API + "/api/v1" + path, method, token, payload, headers)


def page(name: str, token: str, extra: str = "", headers=None):
    url = "/stamps?" + urllib.parse.urlencode({
        "fromUtc": FROM, "toUtcExclusive": TO, "offset": 0, "limit": 50
    }) + extra
    result = must_status(name, api(url, token=token, headers=headers), 200)[1]
    return json.loads(result)


def summary(token: str, extra: str = "", headers=None):
    url = "/stamps/summary?" + urllib.parse.urlencode({
        "fromUtc": FROM, "toUtcExclusive": TO
    }) + extra
    return json.loads(must_status("registry summary", api(url, token=token, headers=headers), 200)[1])


def daily(token: str, start: str, end: str, extra: str = "", headers=None):
    url = "/stamps/daily?" + urllib.parse.urlencode({
        "fromUtc": start, "toUtcExclusive": end
    }) + extra
    raw = must_status("tenant-bound daily counts", api(url, token=token, headers=headers), 200)[1]
    return json.loads(raw)


def audit(token: str, extra: str = "", headers=None):
    url = "/audit?" + urllib.parse.urlencode({
        "fromUtc": FROM, "toUtcExclusive": TO
    }) + extra
    return json.loads(must_status("tenant audit listing", api(url, token=token, headers=headers), 200)[1])


def export(token: str, extra: str = "", headers=None):
    url = "/stamps/export?" + urllib.parse.urlencode({
        "fromUtc": FROM, "toUtcExclusive": TO
    }) + extra
    result = api(url, token=token, headers=headers)
    hdrs, raw = must_status("period export ZIP", result, 200)
    if "no-store" not in hdrs.get("Cache-Control", "").lower():
        raise AssertionError("Tenant evidence ZIP is missing no-store")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        names = set(archive.namelist())
        data = {key: archive.read(key) for key in names if key.startswith("tokens/")}
    return manifest, data


def seed_ci_canaries():
    # No new privileged DB role; the test fixture runs with the already existing
    # disposable PostgreSQL owner through docker compose exec. API requests
    # continue to run using restricted temporalmark_api SQL credentials.
    def stamp(id, org, der, digest, marker):
        return f"""
        INSERT INTO public.timestamp_registry
          (id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
           policy_oid, provider_id, token_sha256_hex, validation_state,
           response_der, evidence_reference)
        VALUES ('{id}', '{org}', now(), '2.16.840.1.101.3.4.2.1',
                '{base64.b64encode(digest).decode()}', '1.2.3.4.5.6',
                '{marker}', '{hashlib.sha256(der).hexdigest().upper()}', 0,
                decode('{der.hex()}','hex'), '{marker}');
        """
    sql = f"""
    BEGIN;
    SELECT public.bootstrap_organization(
        '{ORG_B}', 'CI isolation disposable organization B', '{SUB_B}');
    INSERT INTO public.organization_memberships
      (organization_id, subject_id, role, is_active)
    VALUES ('{ORG_B}', '{SUB_DISABLED}', 'tenant_admin', false);
    {stamp(STAMP_A, ORG_A, DER_A, DIGEST_A, 'CI_ONLY_A')}
    {stamp(STAMP_B, ORG_B, DER_B, DIGEST_B, 'CI_ONLY_B')}
    INSERT INTO public.tenant_audit_events
      (id, organization_id, actor_subject_id, action, occurred_utc,
       period_from_utc, period_to_utc_exclusive)
    VALUES
      ('{AUDIT_A}','{ORG_A}','ci-canary-a','period_export_prepared',
       now(), '{FROM}'::timestamptz, '{TO}'::timestamptz),
      ('{AUDIT_B}','{ORG_B}','ci-canary-b','period_export_prepared',
       now(), '{FROM}'::timestamptz, '{TO}'::timestamptz);
    COMMIT;
    """
    process = subprocess.run([
        "docker", "compose", "-f", "docker/compose.yml",
        "exec", "-T", "postgres", "psql", "-X", "-q",
        "-v", "ON_ERROR_STOP=1", "-U", "temporalmark",
        "-d", "temporalmark"
    ], input=sql, text=True, capture_output=True, timeout=35, check=False)
    if process.returncode != 0:
        # Logs may include SQL statements but no secrets. Do not print raw
        # psql stderr or DB/server connection parameters.
        raise AssertionError("CI-only owner bootstrap/canary SQL failed")


def check_unauthed():
    endpoints = [
        ("GET", "/me", None), ("GET", "/stamps", None),
        ("GET", "/stamps/summary", None), ("GET", "/stamps/daily", None), ("GET", "/audit", None),
        ("GET", "/stamps/export", None),
        ("GET", f"/stamps/{STAMP_B}/receipt", None),
        ("POST", "/stamps/issue", {"digestBase64": base64.b64encode(DIGEST_A).decode()})
    ]
    for method, path, body in endpoints:
        must_status(f"anonymous {method} {path}", api(path, method=method, payload=body), 401)
    must_status("malformed bearer", api("/me", token="NOT_A_JWT"), 401)


def check_authorized(token, own_org, own_id, other_id, own_audit, own_der, other_org):
    role = f"org={own_org}"
    me = json.loads(must_status(role + " /me", api("/me", token=token), 200)[1])
    if me.get("organizationId") != own_org or me.get("role") != "tenant_admin":
        raise AssertionError("Keycloak signed scope / DB membership mismatch")

    expected_ids = {own_id}
    actual_ids = {row["id"] for row in page(role + " /stamps", token)}
    if actual_ids != expected_ids:
        raise AssertionError(f"{role}: list leaked a foreign tenant or lost own canary")
    # RED-first #111 integration boundary (backend already supports paging):
    # one real SQL canary per tenant means authenticated offset=1 is empty.
    # Invalid offsets/limits are 400 and cannot select a foreign tenant.
    paging_path = "/stamps?" + urllib.parse.urlencode({
        "fromUtc": FROM, "toUtcExclusive": TO, "offset": 1, "limit": 1
    })
    one_past = json.loads(must_status(
        role + " page offset beyond tenant rows", api(paging_path, token=token), 200)[1])
    if one_past != []:
        raise AssertionError(f"{role}: authenticated offset page included foreign tenant rows")
    for bad in ({"offset": -1, "limit": 50}, {"offset": 0, "limit": 201}):
        path = "/stamps?" + urllib.parse.urlencode({
            "fromUtc": FROM, "toUtcExclusive": TO, **bad
        })
        must_status(role + " invalid page bounds", api(path, token=token), 400)
    spoofed_page_path = paging_path + "&" + urllib.parse.urlencode({
        "organizationId": other_org, "tenantId": other_org
    })
    spoofed_page = json.loads(must_status(role + " page offset spoofed",
        api(spoofed_page_path, token=token, headers={
            "X-Organization-Id": other_org, "X-Tenant-Id": other_org
        }), 200)[1])
    if spoofed_page != []:
        raise AssertionError(f"{role}: page offset headers/query leaked foreign tenant data")
    listed = summary(token)
    if listed.get("organizationId") != own_org or listed.get("count") != 1:
        raise AssertionError(f"{role}: count/organization does not match isolated canary")

    # RED-first #110: one authenticated, tenant-filtered SQL group-by, not
    # a graph derived from the first 50 registry rows or local timezone.
    # Use a 3-day UTC window around disposable canary 'now()', robust even
    # if the signed-Keycloak integration spans a UTC midnight rollover.
    today = datetime.now(timezone.utc).date()
    start_day = today - timedelta(days=1)
    end_day = today + timedelta(days=2)
    start_utc = start_day.isoformat() + "T00:00:00Z"
    end_utc = end_day.isoformat() + "T00:00:00Z"
    daily_result = daily(token, start_utc, end_utc)
    days = daily_result.get("days")
    if (daily_result.get("organizationId") != own_org or
        not isinstance(days, list) or
        [row.get("dateUtc") for row in days] !=
        [(start_day + timedelta(days=i)).isoformat() for i in range(3)] or
        sum(row.get("count", -1) for row in days) != 1 or
        any(row.get("count", 0) < 0 for row in days)):
        raise AssertionError(f"{role}: UTC daily counts not tenant-bound or zero-filled")
    # No query/header tenant selector can change the authenticated principal.
    spoof = "&" + urllib.parse.urlencode({"organizationId": other_org, "tenantId": other_org})
    headers = {"X-Organization-Id": other_org, "X-Tenant-Id": other_org}
    spoof_result = daily(token, start_utc, end_utc, spoof, headers)
    if spoof_result.get("organizationId") != own_org or spoof_result.get("days") != days:
        raise AssertionError(f"{role}: daily counts leaked another organization on spoofed selector")
    must_status("daily rejects nonmidnight bounds",
                api("/stamps/daily?" + urllib.parse.urlencode({
                    "fromUtc": start_utc.replace("00:00:00Z", "00:01:00Z"),
                    "toUtcExclusive": end_utc
                }), token=token), 400)
    must_status("daily rejects unbounded dates",
                api("/stamps/daily?" + urllib.parse.urlencode({
                    "fromUtc": "2026-01-01T00:00:00Z",
                    "toUtcExclusive": "2026-02-03T00:00:00Z"
                }), token=token), 400)

    found = audit(token)
    ids = {record["id"] for record in found}
    if own_audit not in ids or other_id in ids:
        raise AssertionError(f"{role}: audit canary missing or foreign")
    if any(record.get("organizationId") != own_org for record in found):
        raise AssertionError(f"{role}: foreign tenant audit event returned")

    hdrs, receipt = must_status("own receipt", api(f"/stamps/{own_id}/receipt", token=token), 200)
    if receipt != own_der or "no-store" not in hdrs.get("Cache-Control", "").lower():
        raise AssertionError(f"{role}: receipt does not match verified canary or no-store absent")
    must_status("foreign receipt is indistinguishable from nonexistent",
                api(f"/stamps/{other_id}/receipt", token=token), 404)

    manifest, blobs = export(token)
    names = {entry["Id"] for entry in manifest["entries"]}
    if (manifest["organizationId"] != own_org or manifest["count"] != 1 or
            names != expected_ids or
            blobs != {f"tokens/{own_id.replace('-', '')}.tsr": own_der}):
        raise AssertionError(f"{role}: ZIP manifest or evidence leaked foreign canary")
    acts = {record["action"] for record in audit(token)}
    if not {"PeriodExportPrepared", "ReceiptDownloadPrepared"}.issubset(acts):
        raise AssertionError(f"{role}: access preparation audit events missing")

    # The tenant selector comes only from the JWT and active SQL membership.
    evil_headers = {"X-Organization-Id": other_org, "X-Tenant-Id": other_org}
    override = "&" + urllib.parse.urlencode({
        "organization_id": other_org, "tenantId": other_org
    })
    if {row["id"] for row in page(role + " spoofed query/header", token, override, evil_headers)} != expected_ids:
        raise AssertionError(f"{role}: spoofed query/header changed registry scope")
    if summary(token, override, evil_headers)["count"] != 1:
        raise AssertionError(f"{role}: spoofed summary changed scope")
    if any(row["organizationId"] != own_org for row in audit(token, override, evil_headers)):
        raise AssertionError(f"{role}: spoofed audit changed scope")
    spoofed_zip, blobs = export(token, override, evil_headers)
    if spoofed_zip["organizationId"] != own_org or {r["Id"] for r in spoofed_zip["entries"]} != expected_ids:
        raise AssertionError(f"{role}: spoofed ZIP leaked cross-tenant data")


def main():
    if os.environ.get("TEMPORALMARK_CI_API_ISOLATION") != "1":
        raise AssertionError("Explicit CI-only fixture gate required")
    # Literal localhost targets; do not support an environment-configurable
    # production hostname or operator-supplied database URL.
    well_known = checked_http(IDP + "/realms/temporalmark/.well-known/openid-configuration")
    _, raw = must_status("local disposable IdP metadata", well_known, 200)
    if json.loads(raw).get("issuer") != ISSUER:
        raise AssertionError("Refusing to use unexpected OIDC issuer")
    if checked_http(API + "/healthz")[0] != 200:
        raise AssertionError("Real compiled API is unavailable")

    check_unauthed()
    # TDD RED: this distinct CI principal does not exist until the
    # separate Keycloak development realm fixture is deliberately added.
    b_token = keycloak_token("demo-tenant-b", "local-tenant-b-only")
    a_token = keycloak_token("demo-admin", "local-dev-only")
    member_token = keycloak_token("demo-tenant-member", "local-member-only")
    disabled_token = keycloak_token("demo-tenant-disabled", "local-disabled-only")
    no_org_token = keycloak_token("demo-isolation-no-org", "local-no-org-only")
    for label, token, org, sub in [
        ("A", a_token, ORG_A, SUB_A),
        ("B", b_token, ORG_B, SUB_B)
    ]:
        claims = jwt_claims_untrusted(token)
        if (claims.get("organization_id") != org or claims.get("sub") != sub
                or claims.get("iss") != ISSUER or "temporalmark-api" not in claims.get("aud", [])):
            raise AssertionError(f"Disposable signed {label} token lacks intended scope")
        if claims.get("exp", 0) <= time.time() + 15:
            raise AssertionError(f"Disposable signed {label} token is already near expiry")

    must_status("B token before organization membership", api("/me", token=b_token), 403)
    must_status("A real DB admin before canary insert", api("/me", token=a_token), 200)
    must_status("signed identity with no organization", api("/me", token=no_org_token), 403)
    must_status("signed member not admin", api("/me", token=member_token), 403)
    must_status("signed B user without enabled DB membership", api("/me", token=disabled_token), 403)

    # Independently issued signed JWT with wrong audience must be 401, NOT
    # 403, because it must never reach the business membership guard.
    wrong_aud = keycloak_token("demo-tenant-b", "local-tenant-b-only", BAD_AUDIENCE_CLIENT)
    if "temporalmark-api" in jwt_claims_untrusted(wrong_aud).get("aud", []):
        raise AssertionError("Wrong-audience Keycloak client accidentally grants API audience")
    must_status("signed wrong audience", api("/me", token=wrong_aud), 401)
    master = keycloak_token("local-admin", "dev-only-change-me", "admin-cli", "master")
    if jwt_claims_untrusted(master).get("iss") == ISSUER:
        raise AssertionError("Wrong-issuer token is not from independent master realm")
    must_status("signed wrong issuer", api("/me", token=master), 401)

    short_lived = keycloak_token("demo-tenant-b", "local-tenant-b-only", EXPIRING_CLIENT)
    expires = int(jwt_claims_untrusted(short_lived).get("exp", 0))
    remaining = expires - time.time()
    if remaining < 0 or remaining > 12:
        raise AssertionError("Keycloak short-lived client must really issue <=12s token")
    time.sleep(max(0, expires - time.time()) + 2)
    must_status("authentic expired signed JWT", api("/me", token=short_lived), 401)

    seed_ci_canaries()
    must_status("B DB-authorized tenant admin", api("/me", token=b_token), 200)
    must_status("inactive B DB membership", api("/me", token=disabled_token), 403)
    must_status("signed tenant_member without admin", api("/me", token=member_token), 403)
    check_authorized(a_token, ORG_A, STAMP_A, STAMP_B, AUDIT_A, DER_A, ORG_B)
    check_authorized(b_token, ORG_B, STAMP_B, STAMP_A, AUDIT_B, DER_B, ORG_A)

    # Explicit body scope forging cannot override the server-selected org.
    payload = {"digestBase64": base64.b64encode(DIGEST_A).decode(),
               "organizationId": ORG_B, "tenantId": ORG_B}
    must_status("authorized A no external TSA => NO issuance", api(
        "/stamps/issue", token=a_token, method="POST", payload=payload), 503)
    must_status("inactive member cannot access daily counts", api(
        "/stamps/daily?fromUtc=2026-11-01T00%3A00%3A00Z&toUtcExclusive=2026-11-02T00%3A00%3A00Z",
        token=disabled_token), 403)
    must_status("inactive member may never issue", api(
        "/stamps/issue", token=disabled_token, method="POST", payload=payload), 403)
    if summary(a_token)["count"] != 1 or summary(b_token)["count"] != 1:
        raise AssertionError("Disabled external TSA accidentally minted an evidence record")
    print("PASS: real Keycloak-signed JWT 401/403; two isolated PostgreSQL tenants; "
          "real API list/summary/UTC daily/TSR/ZIP/audit; header/query/body spoofing; "
          "inactive membership; no qualified issuance")


if __name__ == "__main__":
    main()
