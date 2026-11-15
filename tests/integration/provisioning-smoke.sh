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

cli=(dotnet run --project src/backend/applications/TemporalMark.Provisioner/TemporalMark.Provisioner.csproj --configuration Release --)
operator_sub="00000000-0000-0000-0000-000000000002"
admin_sub="00000000-0000-0000-0000-000000000003"

"${cli[@]}" request --organization-name "CI verification org" \
  --operator-token-file "$temp_dir/operator.jwt" \
  --first-admin-token-file "$temp_dir/first-admin.jwt" > "$temp_dir/requested.log"
request_id="$(sed -n 's/^Approval requested: //p' "$temp_dir/requested.log")"
[[ "$request_id" =~ ^[0-9a-f-]{36}$ ]] || { echo "Missing approval request ID" >&2; exit 1; }

# No enrollment before the independent reviewer's signoff.
if "${cli[@]}" complete --request-id "$request_id" \
    --organization-name "CI verification org" \
    --operator-token-file "$temp_dir/operator.jwt" \
    --first-admin-token-file "$temp_dir/first-admin.jwt" > "$temp_dir/no-approval.log" 2>&1; then
    echo "SECURITY FAILURE: unapproved organization was created" >&2; exit 1
fi
if "${cli[@]}" approve --request-id "$request_id" \
    --organization-name "Wrong organization" \
    --expected-initial-admin-sub "$admin_sub" --expected-operator-sub "$operator_sub" \
    --approver-token-file "$temp_dir/approver.jwt" > "$temp_dir/changed-scope.log" 2>&1; then
    echo "SECURITY FAILURE: mismatched organization was approved" >&2; exit 1
fi

"${cli[@]}" approve --request-id "$request_id" \
  --organization-name "CI verification org" \
  --expected-initial-admin-sub "$admin_sub" --expected-operator-sub "$operator_sub" \
  --approver-token-file "$temp_dir/approver.jwt" > "$temp_dir/approved.log"
grep -Fq "Approval recorded: $request_id" "$temp_dir/approved.log"

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
    ("demo-approver", "local-approver-only", "approver-fresh.jwt")
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

"${cli[@]}" approve --request-id "$revoked_id" \
  --organization-name "Revoked first admin" \
  --expected-initial-admin-sub "$admin_sub" --expected-operator-sub "$operator_sub" \
  --approver-token-file "$temp_dir/approver-fresh.jwt" > "$temp_dir/revoked-approved.log"

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
echo "Keycloak approved workflow, role/approval/replay gates and disabled-account denial passed."
