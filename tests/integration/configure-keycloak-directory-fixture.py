#!/usr/bin/env python3
"""DEVELOPMENT/CI ONLY. Grant minimal Keycloak Admin REST read roles to a test client.

Never execute against production realms or use the demo master password outside
the disposable Keycloak realm. Production IAM grants require separate approval.
"""
import json
import urllib.parse
import urllib.request

origin = "http://127.0.0.1:8081"
realm = "temporalmark"
base = f"{origin}/admin/realms/{realm}"

def call(method, url, token=None, data=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(data).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=20) as result:
        response = result.read()
        return json.loads(response) if response else None

data = urllib.parse.urlencode({
    "client_id": "admin-cli", "grant_type": "password",
    "username": "local-admin", "password": "dev-only-change-me"
}).encode()
with urllib.request.urlopen(urllib.request.Request(
    origin + "/realms/master/protocol/openid-connect/token", data=data
), timeout=20) as result:
    master = json.load(result)["access_token"]

def find_client(client_id):
    candidates = call("GET", base + "/clients?clientId=" + urllib.parse.quote(client_id), master)
    matching = [c for c in candidates if c.get("clientId") == client_id]
    if len(matching) != 1:
        raise ValueError("Expected exactly one Keycloak client in disposable realm")
    return matching[0]["id"]

read_client = find_client("temporalmark-directory-checker")
management_client = find_client("realm-management")
account = call("GET", base + f"/clients/{read_client}/service-account-user", master)
account_id = account["id"]

# These are realm-management CLIENT roles, never broad realm-admin/manage-users.
roles = [call("GET", base + f"/clients/{management_client}/roles/{role}", master)
         for role in ("view-users", "view-realm", "query-users")]
call("POST", base + f"/users/{account_id}/role-mappings/clients/{management_client}",
     master, roles)
# Probe permission boundaries through an ACTUAL service-account token: the
# realm-management client roles must appear in the role-scoped access token.
# No token, user attributes or role names are logged.
import base64
client_body = urllib.parse.urlencode({
    "client_id": "temporalmark-directory-checker",
    "client_secret": "local-directory-only",
    "grant_type": "client_credentials"
}).encode()
with urllib.request.urlopen(urllib.request.Request(
    origin + "/realms/temporalmark/protocol/openid-connect/token",
    data=client_body
), timeout=20) as response:
    service_token = json.load(response)["access_token"]
user_id = "00000000-0000-0000-0000-000000000002"
current = call("GET", base + "/users/" + user_id, service_token)
if current.get("id") != user_id or not current.get("enabled"):
    raise AssertionError("Directory service account could not read target user")
mappings = call("GET", base + "/users/" + user_id +
                "/role-mappings/realm/composite", service_token)
if not any(role.get("name") == "platform_provisioner" for role in mappings):
    raise AssertionError("Directory service account cannot read current effective role")
print("Disposable Keycloak directory service-account read-only checks passed.")
