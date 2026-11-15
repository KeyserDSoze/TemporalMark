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
    ("demo-initial-admin", "local-admin-only", "first-admin.jwt")
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
export PROVISIONING_ALLOW_HTTP_LOOPBACK=true
# Confidential Keycloak client is for this disposable CI realm ONLY.
export PROVISIONING_LIVE_PROVIDER=keycloak
export PROVISIONING_INTROSPECTION_CLIENT_ID="temporalmark-live-introspector"
export PROVISIONING_INTROSPECTION_CLIENT_SECRET="local-introspect-only"
export TEMPORALMARK_PROVISIONING_DB="Host=127.0.0.1;Port=5432;Database=temporalmark;Username=temporalmark_provisioner;Password=local-provisioner-only"

cmd=(dotnet run --project src/backend/applications/TemporalMark.Provisioner/TemporalMark.Provisioner.csproj --configuration Release --
    --organization-name "CI verification org"
    --operator-token-file "$temp_dir/operator.jwt"
    --first-admin-token-file "$temp_dir/first-admin.jwt")

"${cmd[@]}" > "$temp_dir/success.log"
grep -Eq '^Organization created: [0-9a-f-]{36}$' "$temp_dir/success.log"

# Same OIDC proofs cannot be used for a second organization (SQL unique token hashes).
if "${cmd[@]}" > "$temp_dir/replay.log" 2>&1; then
    echo "SECURITY FAILURE: replayed enrollment was accepted" >&2
    exit 1
fi

# Identity for first administrator cannot authenticate as a platform provisioner.
if dotnet run --project src/backend/applications/TemporalMark.Provisioner/TemporalMark.Provisioner.csproj --configuration Release -- \
    --organization-name "Incorrect role" \
    --operator-token-file "$temp_dir/first-admin.jwt" \
    --first-admin-token-file "$temp_dir/operator.jwt" > "$temp_dir/invalid.log" 2>&1; then
    echo "SECURITY FAILURE: operator/admin role swap was accepted" >&2
    exit 1
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
    ("demo-initial-admin", "local-admin-only", "first-admin-fresh.jwt")
]:
    token = form(realm + "/protocol/openid-connect/token", {
        "client_id": "temporalmark-local-provisioning-tests",
        "grant_type": "password", "username": username, "password": password
    })["access_token"]
    path = destination / filename
    path.write_text(token)
    os.chmod(path, 0o600)

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
if dotnet run --project src/backend/applications/TemporalMark.Provisioner/TemporalMark.Provisioner.csproj --configuration Release -- \
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
echo "Controlled live Keycloak token checks, disabled-account denial and replay protection passed."
