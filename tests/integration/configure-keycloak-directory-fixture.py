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
print("Disposable directory service client granted Keycloak read-only user/realm roles.")
