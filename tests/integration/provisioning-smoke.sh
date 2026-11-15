#!/usr/bin/env bash
# GitHub Actions development only. No real customer credentials or source files.
set -euo pipefail
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT
umask 077

# Keycloak dev fixture grants issue short-lived signed tokens to two DISTINCT users.
# Never use password grants, embedded fixture secrets or local HTTP in production.
python3 - "$temp_dir" <<'PY'
import json
import os
import pathlib
import sys
import urllib.parse
import urllib.request

destination = pathlib.Path(sys.argv[1])
endpoint = "http://127.0.0.1:8081/realms/temporalmark/protocol/openid-connect/token"
accounts = [
    ("demo-provisioner", "local-provisioner-only", "operator.jwt"),
    ("demo-initial-admin", "local-admin-only", "first-admin.jwt"),
    ("demo-approver", "local-approver-only", "approver.jwt")
]
for username, password, filename in accounts:
    data = urllib.parse.urlencode({
        "client_id": "temporalmark-local-provisioning-tests",
        "grant_type": "password",
        "username": username,
        "password": password,
        "scope": "openid"
    }).encode()
    with urllib.request.urlopen(urllib.request.Request(endpoint, data=data), timeout=20) as response:
        token = json.load(response)["access_token"]
    file = destination / filename
    file.write_text(token, encoding="utf-8")
    os.chmod(file, 0o600)
PY

export PROVISIONING_OIDC_ISSUER="http://localhost:8081/realms/temporalmark"
export PROVISIONING_OPERATOR_AUDIENCE="temporalmark-provisioner"
export PROVISIONING_ADMIN_AUDIENCE="temporalmark-api"
export PROVISIONING_APPROVER_AUDIENCE="temporalmark-approval"
# Disposable CI uses password grant and has NO MFA. Strict production policy
# cannot be disabled for any other issuer/subject.
export PROVISIONING_APPROVER_REQUIRED_ACR="urn:temporalmark:loa:2"
export PROVISIONING_DEVELOPMENT_PASSWORD_GRANT_NO_MFA=true
export PROVISIONING_ALLOW_HTTP_LOOPBACK=true
# Configure dedicated read-only service-account role grants via Keycloak Admin REST.
# This setup uses disposable CI realm admin credentials and is FORBIDDEN in production.
python3 tests/integration/configure-keycloak-directory-fixture.py
# Confidential Keycloak client is for this disposable CI realm ONLY.
export PROVISIONING_LIVE_PROVIDER=keycloak
export PROVISIONING_INTROSPECTION_CLIENT_ID="temporalmark-live-introspector"
export PROVISIONING_INTROSPECTION_CLIENT_SECRET="local-introspect-only"
export PROVISIONING_DIRECTORY_CLIENT_ID="temporalmark-directory-checker"
export PROVISIONING_DIRECTORY_CLIENT_SECRET="local-directory-only"
export TEMPORALMARK_PROVISIONING_DB="Host=127.0.0.1;Port=5432;Database=temporalmark;Username=temporalmark_provisioner;Password=local-provisioner-only"
export TEMPORALMARK_APPROVER_DB="Host=127.0.0.1;Port=5432;Database=temporalmark;Username=temporalmark_approver;Password=local-approver-only"

# Read-only confirmation: the denied operation must not append any tenant audit.
count_events() {
    docker compose -f docker/compose.yml exec -T postgres \
        psql -U temporalmark -d temporalmark -tAc 'SELECT count(*) FROM organization_provisioning_events'
}

cli=(dotnet run --project src/backend/applications/TemporalMark.Provisioner/TemporalMark.Provisioner.csproj --configuration Release --)
operator_sub="00000000-0000-0000-0000-000000000002"
admin_sub="00000000-0000-0000-0000-000000000003"

"${cli[@]}" request --organization-name "CI verification org" \
  --operator-token-file "$temp_dir/operator.jwt" \
  --first-admin-token-file "$temp_dir/first-admin.jwt" > "$temp_dir/requested.log"
request_id="$(sed -n 's/^Approval requested: //p' "$temp_dir/requested.log")"
[[ "$request_id" =~ ^[0-9a-f-]{36}$ ]] || { echo "Missing approval request ID" >&2; exit 1; }

# Reviewer independently fetches ORIGINAL immutable request scope using only
# approver JWT + ID. No operator-supplied name or subject values are displayed.
"${cli[@]}" review --request-id "$request_id" \
  --approver-token-file "$temp_dir/approver.jwt" > "$temp_dir/review.log"
grep -Fq "Organization: CI verification org" "$temp_dir/review.log"
grep -Fq "Operator subject: $operator_sub" "$temp_dir/review.log"
grep -Fq "Initial admin subject: $admin_sub" "$temp_dir/review.log"
review_hash="$(sed -n 's/^Review SHA-256: //p' "$temp_dir/review.log")"
[[ "$review_hash" =~ ^[0-9A-F]{64}$ ]] || {
    echo "SECURITY FAILURE: missing canonical reviewer SHA-256" >&2; exit 1
}
if "${cli[@]}" review --request-id "00000000-0000-0000-0000-000000000001" \
    --approver-token-file "$temp_dir/approver.jwt" > "$temp_dir/missing-review.log" 2>&1; then
    echo "SECURITY FAILURE: reviewer could see a nonexistent request" >&2; exit 1
fi

# No enrollment before the independent reviewer's signoff.
if "${cli[@]}" complete --request-id "$request_id" \
    --organization-name "CI verification org" \
    --operator-token-file "$temp_dir/operator.jwt" \
    --first-admin-token-file "$temp_dir/first-admin.jwt" > "$temp_dir/no-approval.log" 2>&1; then
    echo "SECURITY FAILURE: unapproved organization was created" >&2; exit 1
fi
if "${cli[@]}" approve --request-id "$request_id" \
    --review-sha256 "0000000000000000000000000000000000000000000000000000000000000000" \
    --approver-token-file "$temp_dir/approver.jwt" > "$temp_dir/changed-scope.log" 2>&1; then
    echo "SECURITY FAILURE: mismatched organization was approved" >&2; exit 1
fi

# The disposable password-grant approver token has NO MFA. Without the
# tightly scoped fixture exception it MUST fail even though role and JWT are valid.
if PROVISIONING_DEVELOPMENT_PASSWORD_GRANT_NO_MFA=false "${cli[@]}" approve --request-id "$request_id" \
    --review-sha256 "$review_hash" \
    --approver-token-file "$temp_dir/approver.jwt" > "$temp_dir/no-mfa.log" 2>&1; then
    echo "SECURITY FAILURE: password-only approver accepted without explicit test exception" >&2
    exit 1
fi
if env -u PROVISIONING_APPROVER_REQUIRED_ACR "${cli[@]}" approve --request-id "$request_id" \
    --review-sha256 "$review_hash" \
    --approver-token-file "$temp_dir/approver.jwt" > "$temp_dir/no-policy.log" 2>&1; then
    echo "SECURITY FAILURE: approver accepted without pinned ACR policy" >&2
    exit 1
fi

"${cli[@]}" approve --request-id "$request_id" \
  --review-sha256 "$review_hash" \
  --approver-token-file "$temp_dir/approver.jwt" > "$temp_dir/approved.log"
grep -Fq "Approval recorded: $request_id" "$temp_dir/approved.log"
if "${cli[@]}" review --request-id "$request_id" \
    --approver-token-file "$temp_dir/approver.jwt" > "$temp_dir/after-approval.log" 2>&1; then
    echo "SECURITY FAILURE: approved request remains reviewable" >&2; exit 1
fi
# The existing password-grant fixture MUST be labeled NON_MFA in the audit.
# Do not silently promote its tokens to assurance of a second factor.
fixture_kind="$(docker compose -f docker/compose.yml exec -T postgres psql -U temporalmark     -d temporalmark -tAc "SELECT approver_assurance_kind FROM organization_enrollment_requests WHERE id='$request_id'")"
test "$fixture_kind" = "DISPOSABLE_PASSWORD_ONLY" || {
    echo "SECURITY FAILURE: password-only CI approver mislabeled as strong authentication" >&2
    exit 1
}

"${cli[@]}" complete --request-id "$request_id" \
  --organization-name "CI verification org" \
  --operator-token-file "$temp_dir/operator.jwt" \
  --first-admin-token-file "$temp_dir/first-admin.jwt" > "$temp_dir/success.log"
grep -Fq "Organization created: $request_id" "$temp_dir/success.log"

if "${cli[@]}" complete --request-id "$request_id" \
    --organization-name "CI verification org" \
    --operator-token-file "$temp_dir/operator.jwt" \
    --first-admin-token-file "$temp_dir/first-admin.jwt" > "$temp_dir/replay.log" 2>&1; then
    echo "SECURITY FAILURE: replayed approval" >&2; exit 1
fi
if "${cli[@]}" request --organization-name "Incorrect role" \
    --operator-token-file "$temp_dir/first-admin.jwt" \
    --first-admin-token-file "$temp_dir/operator.jwt" > "$temp_dir/invalid.log" 2>&1; then
    echo "SECURITY FAILURE: operator/admin role swap accepted" >&2; exit 1
fi

# A fresh, signed admin JWT that was valid at issuance MUST be denied if
# the Keycloak account is disabled AFTER its token was issued.
python3 - "$temp_dir" <<'PY'
import json
import os
import pathlib
import sys
import urllib.parse
import urllib.request

destination = pathlib.Path(sys.argv[1])
base = "http://127.0.0.1:8081"
realm = base + "/realms/temporalmark"
def form(url, body, headers=None):
    encoded = urllib.parse.urlencode(body).encode()
    with urllib.request.urlopen(
        urllib.request.Request(url, data=encoded, headers=headers or {}), timeout=20
    ) as response:
        return json.load(response)

for username, password, filename in [
    ("demo-provisioner", "local-provisioner-only", "operator-fresh.jwt"),
    ("demo-initial-admin", "local-admin-only", "first-admin-fresh.jwt"),
    ("demo-approver", "local-approver-only", "approver-fresh.jwt"),
    ("demo-provisioner", "local-provisioner-only", "operator-role.jwt"),
    ("demo-initial-admin", "local-admin-only", "admin-role.jwt"),
    ("demo-approver", "local-approver-only", "approver-role.jwt")
]:
    token = form(realm + "/protocol/openid-connect/token", {
        "client_id": "temporalmark-local-provisioning-tests",
        "grant_type": "password", "username": username, "password": password
    })["access_token"]
    path = destination / filename
    path.write_text(token)
    os.chmod(path, 0o600)

PY

"${cli[@]}" request --organization-name "Revoked first admin" \
  --operator-token-file "$temp_dir/operator-fresh.jwt" \
  --first-admin-token-file "$temp_dir/first-admin-fresh.jwt" > "$temp_dir/revoked-request.log"
revoked_id="$(sed -n 's/^Approval requested: //p' "$temp_dir/revoked-request.log")"
[[ "$revoked_id" =~ ^[0-9a-f-]{36}$ ]] || { echo "Missing second request ID" >&2; exit 1; }
"${cli[@]}" review --request-id "$revoked_id" \
  --approver-token-file "$temp_dir/approver-fresh.jwt" > "$temp_dir/revoked-review.log"
revoked_review_hash="$(sed -n 's/^Review SHA-256: //p' "$temp_dir/revoked-review.log")"
[[ "$revoked_review_hash" =~ ^[0-9A-F]{64}$ ]] || { echo "Missing review digest" >&2; exit 1; }

"${cli[@]}" approve --request-id "$revoked_id" \
  --review-sha256 "$revoked_review_hash" \
  --approver-token-file "$temp_dir/approver-fresh.jwt" > "$temp_dir/revoked-approved.log"

# Separate pending request to prove that removing an approver's CURRENT directory
# role denies approval, even with an independently signed, still-unexpired JWT.
"${cli[@]}" request --organization-name "Removed approver current role" \
  --operator-token-file "$temp_dir/operator-role.jwt" \
  --first-admin-token-file "$temp_dir/admin-role.jwt" > "$temp_dir/role-request.log"
role_request_id="$(sed -n 's/^Approval requested: //p' "$temp_dir/role-request.log")"
[[ "$role_request_id" =~ ^[0-9a-f-]{36}$ ]] || { echo "Missing role-test request ID" >&2; exit 1; }
"${cli[@]}" review --request-id "$role_request_id" \
  --approver-token-file "$temp_dir/approver-role.jwt" > "$temp_dir/role-review.log"
role_review_hash="$(sed -n 's/^Review SHA-256: //p' "$temp_dir/role-review.log")"
[[ "$role_review_hash" =~ ^[0-9A-F]{64}$ ]] || { echo "Missing role-review digest" >&2; exit 1; }

# Disable the admin only AFTER a valid, independent approval has been recorded.
python3 - "$temp_dir" <<'PY'
import json
import pathlib
import sys
import urllib.parse
import urllib.request
destination = pathlib.Path(sys.argv[1])
base = "http://127.0.0.1:8081"
realm = base + "/realms/temporalmark"
def form(url, body, headers=None):
    encoded = urllib.parse.urlencode(body).encode()
    with urllib.request.urlopen(
        urllib.request.Request(url, data=encoded, headers=headers or {}), timeout=20
    ) as response:
        return json.load(response)

admin_token = form(base + "/realms/master/protocol/openid-connect/token", {
    "client_id": "admin-cli", "grant_type": "password",
    "username": "local-admin", "password": "dev-only-change-me"
})["access_token"]
admin_user_id = "00000000-0000-0000-0000-000000000003"
fresh_admin = (destination / "first-admin-fresh.jwt").read_text()

def introspect(token):
    return form(realm + "/protocol/openid-connect/token/introspect", {
        "token": token, "token_type_hint": "access_token",
        "client_id": "temporalmark-live-introspector",
        "client_secret": "local-introspect-only"
    })

if not introspect(fresh_admin).get("active"):
    raise AssertionError("Fresh valid Keycloak user was rejected before disable")

disable = urllib.request.Request(
    base + "/admin/realms/temporalmark/users/" + admin_user_id,
    data=json.dumps({"enabled": False}).encode(),
    method="PUT",
    headers={"Authorization": "Bearer " + admin_token, "Content-Type": "application/json"}
)
with urllib.request.urlopen(disable, timeout=20) as response:
    if response.status != 204:
        raise AssertionError("Failed to disable Keycloak test identity")

if introspect(fresh_admin).get("active") is not False:
    raise AssertionError("Keycloak should mark disabled user's access token inactive")
PY

count_before="$(docker compose -f docker/compose.yml exec -T postgres \
    psql -U temporalmark -d temporalmark -tAc 'SELECT count(*) FROM organization_provisioning_events')"
if "${cli[@]}" complete --request-id "$revoked_id" \
    --organization-name "Revoked first admin" \
    --operator-token-file "$temp_dir/operator-fresh.jwt" \
    --first-admin-token-file "$temp_dir/first-admin-fresh.jwt" > "$temp_dir/disabled.log" 2>&1; then
    echo "SECURITY FAILURE: disabled user was enrolled despite inactive token" >&2
    exit 1
fi
count_after="$(docker compose -f docker/compose.yml exec -T postgres \
    psql -U temporalmark -d temporalmark -tAc 'SELECT count(*) FROM organization_provisioning_events')"
test "$count_before" = "$count_after" || {
    echo "SECURITY FAILURE: failed account-status check caused database side effect" >&2
    exit 1
}
# Verify removal of an effective CURRENT realm role after token issuance.
# The service-account directory read is independent of JWT/introspection snapshots.
python3 - "$temp_dir" <<'PY'
import json, pathlib, sys, urllib.parse, urllib.request
base = "http://127.0.0.1:8081"
endpoint = base + "/realms/temporalmark/protocol/openid-connect/token/introspect"
target = (pathlib.Path(sys.argv[1]) / "approver-role.jwt").read_text()
def form(url, body):
    data = urllib.parse.urlencode(body).encode()
    with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=20) as res:
        return json.load(res)
master = form(base + "/realms/master/protocol/openid-connect/token", {
    "client_id": "admin-cli", "grant_type": "password",
    "username": "local-admin", "password": "dev-only-change-me"
})["access_token"]
def request(method, url, data=None):
    headers = {"Authorization": "Bearer " + master, "Accept": "application/json"}
    if data is not None:
        data = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    with urllib.request.urlopen(
        urllib.request.Request(url, data=data, headers=headers, method=method), timeout=20
    ) as response:
        content = response.read()
        return json.loads(content) if content else None
realm = base + "/admin/realms/temporalmark"
approver_id = "00000000-0000-0000-0000-000000000004"
role = request("GET", realm + "/roles/platform_approver")
request("DELETE", realm + "/users/" + approver_id + "/role-mappings/realm", [role])
mapping = request("GET", realm + "/users/" + approver_id + "/role-mappings/realm/composite")
if any(x.get("name") == "platform_approver" for x in mapping):
    raise AssertionError("Keycloak current role mapping should no longer authorize approver")
# This token may still be active and carry the old role because JWTs are
# issuance-time snapshots. The CLI MUST consult the directory independently.
status = form(endpoint, {
    "token": target, "token_type_hint": "access_token",
    "client_id": "temporalmark-live-introspector",
    "client_secret": "local-introspect-only"
})
if status.get("active") is not True:
    raise AssertionError("Role-removal regression requires an otherwise active access token")
PY
count_before_role="$(count_events)"
if "${cli[@]}" approve --request-id "$role_request_id" \
   --review-sha256 "$role_review_hash" \
   --approver-token-file "$temp_dir/approver-role.jwt" > "$temp_dir/role-removed.log" 2>&1; then
    echo "SECURITY FAILURE: revoked directory role was ignored" >&2
    exit 1
fi
count_after_role="$(count_events)"
test "$count_before_role" = "$count_after_role" || {
    echo "SECURITY FAILURE: removed directory role caused DB side effects" >&2; exit 1
}
echo "Independent current-role Keycloak checks, live account denial and approval gates passed."
