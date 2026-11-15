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
echo "Controlled Keycloak OIDC provisioning, role denial and replay rejection passed."
