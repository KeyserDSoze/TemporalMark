#!/usr/bin/env python3
"""CI ONLY: real Keycloak signed JWT, real compiled API and PostgreSQL tenant canaries.

No mock server/membership, no JWT/password/authorization-code output or artifacts.
This script is forbidden against live tenants and requires a disposable Compose stack.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import io
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

# #167: reuse the independent standard-library-only v1 ZIP/SHA256 checker
# on the actual .NET API export bytes, not only synthetic unit fixtures.
import verify_period_export as offline_v1

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
OVERSIZED_LEGACY_STAMP = "cccccccc-cccc-cccc-cccc-cccccccccc82"
OVERSIZED_METADATA_STAMP = "dddddddd-dddd-dddd-dddd-dddddddddd82"
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


def search_imprint(token: str, digest_hex: str, offset: int = 0,
                   limit: int = 50, headers=None, extra_body=None):
    # Authenticated read-only POST: the document imprint never appears
    # in API URL, proxy query string or a log-worthy assertion label.
    payload = {
        "fromUtc": FROM, "toUtcExclusive": TO,
        "digestSha256Hex": digest_hex, "offset": offset, "limit": limit
    }
    payload.update(extra_body or {})
    return api("/stamps/search", token=token, method="POST",
               payload=payload, headers=headers)


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
    # This one wrapper serves both signed-Keycloak tenant A/B and spoofed
    # selector requests. Check EXACTLY the returned ZIP with the stricter
    # offline v1 structure/SHA256 parser before generic zipfile extraction.
    # Never persist/log ZIP bytes or expose tenant/manifest/DER on failure.
    try:
        verified_count = offline_v1.verify_archive(io.BytesIO(raw))
    except offline_v1.ExportVerificationError:
        raise AssertionError(
            "Offline v1 period ZIP structure/SHA256 verification failed") from None
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        names = set(archive.namelist())
        data = {key: archive.read(key) for key in names if key.startswith("tokens/")}
    if manifest["count"] != verified_count:
        raise AssertionError("Offline v1 period ZIP manifest count mismatch")
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
        ("POST", "/stamps/search", {
            "fromUtc": FROM, "toUtcExclusive": TO,
            "digestSha256Hex": DIGEST_A.hex(), "offset": 0, "limit": 50
        }),
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
    # RED-first #114: successful search events must be tenant-bound, with no
    # imprint, match signal, receipt id or period in the event payload.
    audit_prior_to_search = [row for row in audit(token)
                             if row.get("action") == "DocumentImprintSearchPerformed"]
    # RED-first #112: real signed-Keycloak token, disposable canary rows
    # and actual tenant-filtered PostgreSQL exact document-imprint lookup.
    own_digest = DIGEST_A if own_org == ORG_A else DIGEST_B
    foreign_digest = DIGEST_B if own_org == ORG_A else DIGEST_A
    found_meta = json.loads(must_status(role + " own SHA256 lookup",
        search_imprint(token, own_digest.hex().upper()), 200)[1])
    if (found_meta.get("hasMore") is not False or
        {item.get("id") for item in found_meta.get("items", [])} != {own_id} or
        any("responseDer" in item for item in found_meta["items"])):
        raise AssertionError(f"{role}: document-imprint lookup did not isolate own metadata")
    foreign_meta = json.loads(must_status(role + " foreign SHA256 absent",
        search_imprint(token, foreign_digest.hex()), 200)[1])
    if foreign_meta.get("items") != [] or foreign_meta.get("hasMore") is not False:
        raise AssertionError(f"{role}: lookup leaked foreign tenant's document imprint")
    beyond = json.loads(must_status(role + " imprint search second page",
        search_imprint(token, own_digest.hex(), offset=1, limit=1), 200)[1])
    if beyond.get("items") != [] or beyond.get("hasMore") is not False:
        raise AssertionError(f"{role}: lookup offset leaked foreign tenant")
    spoofed = json.loads(must_status(role + " imprint lookup spoofed org",
        search_imprint(token, own_digest.hex(), headers={
            "X-Organization-Id": other_org, "X-Tenant-Id": other_org
        }, extra_body={"organizationId": other_org, "tenantId": other_org}), 200)[1])
    if {item.get("id") for item in spoofed.get("items", [])} != {own_id}:
        raise AssertionError(f"{role}: forged lookup tenant selector changed scope")
    for invalid in ("", "0x" + own_digest.hex(), own_digest.hex() + "0", "Z" * 64):
        must_status(role + " bad document-imprint input",
                    search_imprint(token, invalid), 400)
    must_status(role + " bad document-imprint limit",
                search_imprint(token, own_digest.hex(), limit=51), 400)
    must_status(role + " bad document-imprint offset",
                search_imprint(token, own_digest.hex(), offset=-1), 400)
    search_events = [row for row in audit(token)
                     if row.get("action") == "DocumentImprintSearchPerformed"]
    # Four valid searches above: own, foreign, offset and spoofed body/headers.
    # Seven malformed searches must not be recorded or access the registry.
    if len(search_events) - len(audit_prior_to_search) != 4:
        raise AssertionError(f"{role}: did not append exactly four successful search audit events")
    for event in search_events:
        if (event.get("organizationId") != own_org or
            event.get("actorSubjectId") != jwt_claims_untrusted(token).get("sub") or
            event.get("receiptId") is not None or
            event.get("periodFromUtc") is not None or
            event.get("periodToUtcExclusive") is not None):
            raise AssertionError(f"{role}: search event leaked data or has wrong tenant/principal")
    serialized_events = json.dumps(search_events).lower()
    if own_digest.hex() in serialized_events or foreign_digest.hex() in serialized_events:
        raise AssertionError(f"{role}: sensitive document imprint stored in tenant audit")

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
    # #174: the legitimate 200 returns the original retained DER and
    # appends exactly ONE scoped receipt-prepared audit. Foreign 404 must
    # not prepare a download, and the later oversized A 409 must append ZERO.
    prepared_receipts = [event for event in audit(token)
                         if event.get("action") == "ReceiptDownloadPrepared"]
    if (len(prepared_receipts) != 1 or
        prepared_receipts[0].get("receiptId") != own_id or
        prepared_receipts[0].get("organizationId") != own_org):
        raise AssertionError(f"{role}: normal retained receipt not audited exactly once for own tenant")

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


def assert_search_audit_fail_closed_on_real_postgres_write_denial(token: str):
    # CI-only negative test. Permission changes are made by the disposable
    # PostgreSQL owner and MUST be reverted even if the HTTP assertion fails.
    # No production database endpoint or parameters are accepted.
    def owner_sql(statement: str):
        proc = subprocess.run([
            "docker", "compose", "-f", "docker/compose.yml",
            "exec", "-T", "postgres", "psql", "-X", "-q",
            "-v", "ON_ERROR_STOP=1", "-U", "temporalmark",
            "-d", "temporalmark"
        ], input=statement + "\n", text=True, capture_output=True,
            timeout=35, check=False)
        if proc.returncode != 0:
            raise AssertionError("CI-only audit writer permission exercise failed")

    before = [row["id"] for row in audit(token)
              if row.get("action") == "DocumentImprintSearchPerformed"]
    owner_sql("REVOKE INSERT ON TABLE public.tenant_audit_events FROM temporalmark_runtime_group;")
    try:
        status, _, body = search_imprint(token, DIGEST_A.hex())
        if status != 500:
            raise AssertionError("Audit append outage did not fail closed with HTTP 500")
        if (STAMP_A.encode() in body or DIGEST_A.hex().encode() in body or
                base64.b64encode(DIGEST_A) in body):
            raise AssertionError("Audit outage disclosed registry results or searched imprint")
    finally:
        owner_sql("GRANT INSERT ON TABLE public.tenant_audit_events TO temporalmark_runtime_group;")

    after = [row["id"] for row in audit(token)
             if row.get("action") == "DocumentImprintSearchPerformed"]
    if after != before:
        raise AssertionError("Denied audit append unexpectedly persisted a search event")


def assert_shared_tenant_principal_search_quota(a_token: str, b_token: str):
    # RED-first #116: real PostgreSQL-backed, actor+tenant quotas, not
    # per-process rate limiter or mocked JWT. All test identities disposable.
    before = [row["id"] for row in audit(a_token)
              if row.get("action") == "DocumentImprintSearchPerformed"]
    admissions = 0
    denial = None
    for _ in range(40):
        status, headers, raw = search_imprint(a_token, DIGEST_A.hex())
        if status == 200:
            admissions += 1
            continue
        if status == 429:
            denial = headers, raw
            break
        raise AssertionError(f"Search rate limiter unexpectedly returned HTTP {status}")

    if denial is None or not 1 <= admissions <= 12:
        raise AssertionError("Per-actor search quota did not deny in the bounded HTTP probe")
    headers, raw = denial
    try:
        retry = int(headers.get("Retry-After", ""))
    except ValueError:
        raise AssertionError("429 lacks numeric Retry-After") from None
    if not 1 <= retry <= 60 or "no-store" not in headers.get("Cache-Control", "").lower():
        raise AssertionError("429 lacks bounded retry or no-store")
    if (b"hasMore" in raw or STAMP_A.encode() in raw or
            DIGEST_A.hex().encode() in raw or base64.b64encode(DIGEST_A) in raw):
        raise AssertionError("429 disclosed search match, receipt or confidential imprint")

    # A forged B organization in JSON or headers must never change A's quota.
    must_status("429 ignores forged tenant selector", search_imprint(
        a_token, DIGEST_A.hex(),
        extra_body={"organizationId": ORG_B, "tenantId": ORG_B},
        headers={"X-Organization-Id": ORG_B, "X-Tenant-Id": ORG_B}), 429)
    # Invalid request remains 400 before SQL quota and before any audit.
    must_status("invalid input remains 400 even after quota exhaustion",
                search_imprint(a_token, "bad"), 400)
    # Tenant B's separately authenticated principal is not rate denied by A.
    must_status("independent B tenant quota not exhausted by A",
                search_imprint(b_token, DIGEST_B.hex()), 200)
    after = [row["id"] for row in audit(a_token)
             if row.get("action") == "DocumentImprintSearchPerformed"]
    if len(after) - len(before) != admissions:
        raise AssertionError("Denied or malformed searches unexpectedly appended tenant audit")


def assert_search_rate_store_permission_failure_is_closed(token: str):
    # CI-only: deny the shared SQL rate function on the runtime group.
    # No process-local fallback may answer a search; always restore grant.
    def mutate_grant(sql: str):
        result = subprocess.run([
            "docker", "compose", "-f", "docker/compose.yml",
            "exec", "-T", "postgres", "psql", "-X", "-q",
            "-v", "ON_ERROR_STOP=1", "-U", "temporalmark", "-d", "temporalmark"
        ], input=sql + "\n", text=True, capture_output=True,
            timeout=35, check=False)
        if result.returncode != 0:
            raise AssertionError("CI-only quota privilege change failed")

    mutate_grant("REVOKE EXECUTE ON FUNCTION public.consume_imprint_search_rate(uuid,text) "
                 "FROM temporalmark_runtime_group;")
    try:
        status, _, raw = search_imprint(token, DIGEST_B.hex())
        if status != 500:
            raise AssertionError("Unavailable shared quota gate did not deny search")
        if (STAMP_B.encode() in raw or DIGEST_B.hex().encode() in raw or
                base64.b64encode(DIGEST_B) in raw or b"hasMore" in raw):
            raise AssertionError("Failed quota gate disclosed a document match")
    finally:
        mutate_grant("GRANT EXECUTE ON FUNCTION public.consume_imprint_search_rate(uuid,text) "
                     "TO temporalmark_runtime_group;")
    must_status("shared quota recovered after CI-only SQL grant restoration",
                search_imprint(token, DIGEST_B.hex()), 200)


def assert_search_body_budget_with_signed_chunked_jwt(token: str):
    """#136: prove the actual read-limit, not only a declared Content-Length.

    The already signed real Keycloak JWT is supplied in a CI-only request
    without Content-Length, so an oversized valid JSON body must be rejected
    by Kestrel DURING its model-binding read, with no match or audit data.
    This sends a separate synthetic disposable fixture, never a user file.
    """
    body = json.dumps({
        "digestSha256Hex": DIGEST_A.hex(),
        "fromUtc": FROM,
        "toUtcExclusive": TO,
        "offset": 0,
        "limit": 1,
        "padding": "SYNTHETIC_CHUNKED_PAD_136" * 240,
    }, separators=(",", ":")).encode("utf-8")
    if len(body) <= 4096:
        raise AssertionError("Invalid signed Keycloak chunked CI request fixture")

    conn = http.client.HTTPConnection("127.0.0.1", 8080, timeout=25)
    try:
        conn.putrequest("POST", "/api/v1/stamps/search")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Transfer-Encoding", "chunked")
        conn.putheader("Authorization", "Bearer " + token)
        conn.endheaders()
        conn.send(("%x\r\n" % len(body)).encode("ascii") + body +
                  b"\r\n0\r\n\r\n")
        response = conn.getresponse()
        status = response.status
        result = response.read(8192)
    finally:
        conn.close()

    if status != 413:
        raise AssertionError(
            f"Signed Keycloak chunked oversize returned HTTP {status} instead of 413")
    if any(s in result for s in (
            DIGEST_A.hex().encode("ascii"), b"hasMore",
            b"organizationId", STAMP_A.encode("ascii"))):
        raise AssertionError("Chunked 413 disclosed document or tenant metadata")



def assert_oversized_legacy_other_metadata_is_denied(a_token: str, b_token: str):
    """#176: original SHA-consistent DER, but provider_id has >16KiB UTF8 bytes.

    Runs before the separately seeded oversized DER canary, so denial
    cannot be attributed to older DER or evidence_reference checks.
    All text/DER synthesis happens inside disposable PostgreSQL, not logs.
    """
    digest64 = base64.b64encode(DIGEST_A).decode("ascii")
    token_sha = hashlib.sha256(DER_A).hexdigest().upper()
    command = [
        "docker", "compose", "-f", "docker/compose.yml",
        "exec", "-T", "postgres", "psql", "-X", "-q",
        "-v", "ON_ERROR_STOP=1", "-U", "temporalmark",
        "-d", "temporalmark"
    ]
    sql = f"""
    INSERT INTO public.timestamp_registry
        (id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
         policy_oid, provider_id, token_sha256_hex, validation_state,
         response_der, evidence_reference)
    VALUES ('{OVERSIZED_METADATA_STAMP}', '{ORG_A}', now(),
            '2.16.840.1.101.3.4.2.1', '{digest64}',
            '1.2.3', repeat('P', 16385), '{token_sha}', 0,
            decode('{DER_A.hex()}', 'hex'), NULL::text);
    """
    written = subprocess.run(command, input=sql, text=True, capture_output=True,
                             timeout=35, check=False)
    if written.returncode != 0:
        raise AssertionError("CI-only oversized metadata fixture setup failed")

    # An authorized own-row response must be refused BEFORE any
    # receipt_download_prepared event, and another tenant cannot infer size.
    status, headers, body = api(
        f"/stamps/{OVERSIZED_METADATA_STAMP}/receipt", token=a_token)
    if status != 409 or "no-store" not in headers.get("Cache-Control", "").lower():
        raise AssertionError(f"Over-budget original provider metadata GET contract regressed: HTTP {status}")
    if len(body) > 4096 or any(value in body for value in (
        ORG_A.encode(), OVERSIZED_METADATA_STAMP.encode(), b"CI_ONLY_METADATA_PROJECTION")):
        raise AssertionError("Oversized provider metadata denial disclosed evidence identity")
    must_status("Other tenant metadata-sized receipt stays 404",
                api(f"/stamps/{OVERSIZED_METADATA_STAMP}/receipt", token=b_token), 404)

    q = f"""SELECT count(*) FROM public.tenant_audit_events
        WHERE organization_id = '{ORG_A}'
          AND receipt_id = '{OVERSIZED_METADATA_STAMP}'
          AND action = 'receipt_download_prepared';"""
    checked = subprocess.run(command + ["-t", "-A"], input=q, text=True,
                             capture_output=True, timeout=35, check=False)
    if checked.returncode != 0 or checked.stdout.strip() != "0":
        raise AssertionError("Oversized provider metadata incorrectly prepared receipt audit")

    # No partial page/export, including a preceding normal A record.
    page_url = "/stamps?" + urllib.parse.urlencode({
        "fromUtc": FROM, "toUtcExclusive": TO, "offset": 0, "limit": 50
    })
    page_status, _, page_body = api(page_url, token=a_token)
    if page_status != 500 or any(value in page_body for value in (
        ORG_A.encode(), OVERSIZED_METADATA_STAMP.encode(), b"CI_ONLY_METADATA_PROJECTION")):
        raise AssertionError(f"Invalid provider metadata page gate regressed: HTTP {page_status}")
    b_page = json.loads(must_status(
        "Other signed tenant page still intact after metadata denial",
        api(page_url, token=b_token), 200)[1])
    if len(b_page) != 1 or b_page[0].get("id") != STAMP_B:
        raise AssertionError("Foreign tenant metadata contamination")

    period_url = "/stamps/export?" + urllib.parse.urlencode({
        "fromUtc": FROM, "toUtcExclusive": TO
    })
    q_export = f"""SELECT count(*) FROM public.tenant_audit_events
        WHERE organization_id = '{ORG_A}'
          AND action = 'period_export_prepared'
          AND period_from_utc = '{FROM}'::timestamptz
          AND period_to_utc_exclusive = '{TO}'::timestamptz;"""

    def prepared_exports() -> int:
        result = subprocess.run(command + ["-t", "-A"], input=q_export, text=True,
                                capture_output=True, timeout=35, check=False)
        if result.returncode != 0 or not result.stdout.strip().isdigit():
            raise AssertionError("CI-only metadata export audit scalar failed")
        return int(result.stdout.strip())

    before = prepared_exports()
    zip_status, _, zip_body = api(period_url, token=a_token)
    if zip_status != 413 or len(zip_body) > 4096 or any(value in zip_body for value in (
        ORG_A.encode(), OVERSIZED_METADATA_STAMP.encode(), b"CI_ONLY_METADATA_PROJECTION")):
        raise AssertionError(f"Invalid provider metadata ZIP admission regressed: HTTP {zip_status}")
    if prepared_exports() != before:
        raise AssertionError("Oversized provider metadata incorrectly prepared period export audit")

    # B keeps its original one receipt and readable raw DER.
    _, foreign_zip = must_status("Other signed tenant ZIP remains original",
                                 api(period_url, token=b_token), 200)
    with zipfile.ZipFile(io.BytesIO(foreign_zip)) as archive:
        expected_entry = "tokens/" + STAMP_B.replace("-", "") + ".tsr"
        if archive.namelist().count(expected_entry) != 1:
            raise AssertionError("Foreign tenant ZIP path changed")
        if archive.read(expected_entry) != DER_B:
            raise AssertionError("Foreign tenant retained original receipt changed")
    print("PASS: original SHA-consistent over-16KiB provider metadata: A GET 409/no-store, page 500, ZIP 413, zero prepared audit; B 404 and intact page/ZIP")


def assert_oversized_legacy_receipt_is_not_downloaded(a_token: str, b_token: str):
    """#169 CI-only real SQL/HTTP: >1 MiB retained DER, correct SHA, no 200/audit.

    Run strictly after all ordinary tenant count and search assertions. Only
    the disposable Docker/PG owner seeds this row; real API auth remains
    tenant-scoped and no raw DER, tokens or hash are sent to CI logs.
    """
    size = 1024 * 1024 + 1
    expected_sha = hashlib.sha256(bytes(size)).hexdigest().upper()
    digest64 = base64.b64encode(DIGEST_A).decode("ascii")
    sql = f"""
    INSERT INTO public.timestamp_registry
      (id, organization_id, issued_utc, hash_algorithm_oid, digest_base64,
       policy_oid, provider_id, token_sha256_hex, validation_state,
       response_der, evidence_reference)
    VALUES ('{OVERSIZED_LEGACY_STAMP}', '{ORG_A}', now(),
            '2.16.840.1.101.3.4.2.1', '{digest64}', '1.2.3.4.5.6',
            'CI_ONLY_OVERSIZE', '{expected_sha}', 0,
            decode(repeat('00', {size}), 'hex'), 'CI_ONLY_OVERSIZE');
    """
    command = [
        "docker", "compose", "-f", "docker/compose.yml",
        "exec", "-T", "postgres", "psql", "-X", "-q",
        "-v", "ON_ERROR_STOP=1", "-U", "temporalmark",
        "-d", "temporalmark"
    ]
    written = subprocess.run(
        command, input=sql, text=True, capture_output=True, timeout=35,
        check=False)
    if written.returncode != 0:
        raise AssertionError("CI-only oversized stored receipt fixture setup failed")

    status, headers, body = api(
        f"/stamps/{OVERSIZED_LEGACY_STAMP}/receipt", token=a_token)
    if status != 409:
        raise AssertionError(
            f"Authenticated oversized receipt was not refused with 409 (HTTP {status}; response withheld)")
    if "no-store" not in headers.get("Cache-Control", "").lower():
        raise AssertionError("Refused oversized receipt lacks Cache-Control no-store")
    if (len(body) > 4096 or
        any(private in body for private in (
            ORG_A.encode("ascii"), OVERSIZED_LEGACY_STAMP.encode("ascii"),
            expected_sha.encode("ascii"), b"CI_ONLY_OVERSIZE"))):
        raise AssertionError("Oversized receipt denial disclosed private evidence identifiers")

    must_status("Other tenant oversized receipt remains nonexistent",
                api(f"/stamps/{OVERSIZED_LEGACY_STAMP}/receipt", token=b_token), 404)

    # Use the disposable database owner to count this EXACT rejected
    # receipt's audit markers; avoid a limited paged listing false negative.
    count_sql = f"""SELECT count(*) FROM public.tenant_audit_events
        WHERE organization_id = '{ORG_A}'
          AND receipt_id = '{OVERSIZED_LEGACY_STAMP}'
          AND action = 'receipt_download_prepared';"""
    # -q alone preserves psql's table header/footer: even a zero count
    # prints multiple lines. Request an unaligned, tuples-only scalar so
    # zero versus positive audit counts are distinguished correctly.
    checked = subprocess.run(
        command + ["-t", "-A"], input=count_sql, text=True,
        capture_output=True, timeout=35, check=False)
    if checked.returncode != 0 or checked.stdout.strip() != "0":
        raise AssertionError("Rejected oversized receipt incorrectly prepared a download audit event")
    print("PASS: SHA-consistent oversized legacy DER owner GET 409/no-store, foreign GET 404, zero prepared-download audits")




def assert_oversized_legacy_registry_page_is_denied(a_token: str, b_token: str):
    """#171: after #169's one SHA-consistent oversized A-only row is seeded,
    list API must refuse entire A metadata page, while B stays readable.
    This is a real disposable PostgreSQL + signed Keycloak .NET HTTP probe.
    """
    page_url = "/stamps?" + urllib.parse.urlencode({
        "fromUtc": FROM, "toUtcExclusive": TO, "offset": 0, "limit": 50
    })
    status, headers, body = api(page_url, token=a_token)
    if status != 500:
        raise AssertionError(
            f"SHA-consistent oversized legacy DER was accepted on owner registry page (HTTP {status}; body withheld)")
    if any(private in body for private in (
        ORG_A.encode("ascii"), OVERSIZED_LEGACY_STAMP.encode("ascii"),
        b"CI_ONLY_OVERSIZE")):
        raise AssertionError("Oversized metadata-page denial disclosed private evidence identity")

    # Wrong-tenant records must never poison or appear in B's own valid
    # listing; the original B 1-row test canary remains independently visible.
    b_items = json.loads(must_status(
        "Other signed tenant registry page unaffected by oversized A-only row",
        api(page_url, token=b_token), 200)[1])
    if len(b_items) != 1 or b_items[0].get("id") != STAMP_B:
        raise AssertionError("Other tenant registry page isolation regressed")
    print("PASS: oversized SHA-consistent legacy DER denies A metadata page; B tenant registry remains isolated")




def assert_oversized_legacy_period_export_preserves_413_and_no_audit(a_token: str, b_token: str):
    """#173 / ADR 0131: real PG17 + signed Keycloak export failure audit.

    This runs strictly AFTER the normal tenant/export tests and the A-only
    SHA-consistent oversized legacy DER fixture, never on a real tenant.
    """
    period_url = "/stamps/export?" + urllib.parse.urlencode({
        "fromUtc": FROM, "toUtcExclusive": TO
    })
    command = [
        "docker", "compose", "-f", "docker/compose.yml",
        "exec", "-T", "postgres", "psql", "-X", "-q",
        "-v", "ON_ERROR_STOP=1", "-U", "temporalmark",
        "-d", "temporalmark", "-t", "-A"
    ]
    sql = f"""SELECT count(*) FROM public.tenant_audit_events
        WHERE organization_id = '{ORG_A}' AND action = 'period_export_prepared'
        AND period_from_utc = '{FROM}'::timestamptz
        AND period_to_utc_exclusive = '{TO}'::timestamptz;"""

    def count_prepared():
        checked = subprocess.run(command, input=sql, text=True,
                                 capture_output=True, timeout=35, check=False)
        if checked.returncode != 0 or not checked.stdout.strip().isdigit():
            raise AssertionError("CI-only period export prepared-event count query failed")
        return int(checked.stdout.strip())

    before = count_prepared()
    status, headers, body = api(period_url, token=a_token)
    if status != 413:
        raise AssertionError(
            f"Oversized A-only legacy DER did not retain HTTP 413 on ZIP export (HTTP {status}; body withheld)")
    if len(body) > 4096 or any(private in body for private in (
        ORG_A.encode("ascii"), OVERSIZED_LEGACY_STAMP.encode("ascii"),
        b"CI_ONLY_OVERSIZE", DIGEST_A.hex().encode("ascii"))):
        raise AssertionError("Oversized period-export denial leaked evidence identifiers")
    if count_prepared() != before:
        raise AssertionError("Rejected oversized period ZIP incorrectly appended an export-prepared audit event")

    # B's legitimate single-receipt export must remain successful, private
    # and unmodified while A's oversized legacy row is present.
    _, raw = must_status("Foreign tenant valid ZIP still succeeds",
                         api(period_url, token=b_token), 200)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = [name for name in archive.namelist() if name.endswith(".tsr")]
        if entries != ["tokens/" + STAMP_B.replace("-", "") + ".tsr"]:
            raise AssertionError("B ZIP export contained foreign or missing receipt paths")
        if archive.read(entries[0]) != DER_B:
            raise AssertionError("B ZIP returned altered original retained DER")
        if json.loads(archive.read("manifest.json")).get("count") != 1:
            raise AssertionError("B ZIP manifest is incomplete")
    print("PASS: A SHA-consistent oversized legacy ZIP remains HTTP 413 with zero new prepared-export audits; B retained ZIP 200 and original DER")


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

    # Genuine signed JWT and unknown-length chunked JSON: Kestrel, not
    # Content-Length or the Nginx frontend, must enforce its body read cap.
    assert_search_body_budget_with_signed_chunked_jwt(a_token)

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
    must_status("inactive member cannot search document imprint",
                search_imprint(disabled_token, DIGEST_B.hex()), 403)
    must_status("inactive member cannot access daily counts", api(
        "/stamps/daily?fromUtc=2026-11-01T00%3A00%3A00Z&toUtcExclusive=2026-11-02T00%3A00%3A00Z",
        token=disabled_token), 403)
    must_status("inactive member may never issue", api(
        "/stamps/issue", token=disabled_token, method="POST", payload=payload), 403)
    if summary(a_token)["count"] != 1 or summary(b_token)["count"] != 1:
        raise AssertionError("Disabled external TSA accidentally minted an evidence record")
    assert_search_audit_fail_closed_on_real_postgres_write_denial(a_token)
    assert_shared_tenant_principal_search_quota(a_token, b_token)
    assert_search_rate_store_permission_failure_is_closed(b_token)
    assert_oversized_legacy_other_metadata_is_denied(a_token, b_token)
    assert_oversized_legacy_receipt_is_not_downloaded(a_token, b_token)
    assert_oversized_legacy_registry_page_is_denied(a_token, b_token)
    assert_oversized_legacy_period_export_preserves_413_and_no_audit(a_token, b_token)
    print("PASS: real Keycloak-signed JWT 401/403; two isolated PostgreSQL tenants; "
          "real API list/summary/UTC daily/document-SHA256-search/TSR/ZIP/audit; header/query/body spoofing; "
          "inactive membership; no qualified issuance")


if __name__ == "__main__":
    main()
