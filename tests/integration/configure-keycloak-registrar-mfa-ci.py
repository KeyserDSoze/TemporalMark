#!/usr/bin/env python3
"""DISPOSABLE CI ONLY. Manage a distinct Keycloak MFA registrar fixture.

No real registrar SQL role/login, public enrollment API, WebAuthn key or
approval is provisioned. Never run this script against a production realm.
Credentials below are fixed to a disposable loopback Docker master realm.
"""
import json
import sys
import urllib.parse
import urllib.request

MODES = {"prepare", "remove-registrar-role", "restore-registrar-role", "disable-registrar"}
if len(sys.argv) != 2 or sys.argv[1] not in MODES:
    raise SystemExit("Usage: configure-keycloak-registrar-mfa-ci.py prepare|remove-registrar-role|restore-registrar-role|disable-registrar")
mode = sys.argv[1]

origin = "http://127.0.0.1:8081"
realm = "temporalmark-mfa-ci"
admin = origin + "/admin/realms/" + realm
registrar_id = "00000000-0000-0000-0000-000000000035"
reviewer_id = "00000000-0000-0000-0000-000000000034"


def form(url, fields, token=None):
    encoded = urllib.parse.urlencode(fields).encode("utf-8")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if token:
        headers["Authorization"] = "Bearer " + token
    with urllib.request.urlopen(urllib.request.Request(
        url, data=encoded, headers=headers, method="POST"), timeout=20) as response:
        return json.load(response)


def request(method, path, token, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json", "Authorization": "Bearer " + token}
    if data is not None:
        headers["Content-Type"] = "application/json"
    with urllib.request.urlopen(urllib.request.Request(
        admin + path, data=data, headers=headers, method=method), timeout=20) as response:
        payload = response.read()
        return json.loads(payload) if payload else None


master = form(origin + "/realms/master/protocol/openid-connect/token", {
    "client_id": "admin-cli", "grant_type": "password",
    "username": "local-admin", "password": "dev-only-change-me"
})["access_token"]


def client_id(name):
    results = request("GET", "/clients?clientId=" + urllib.parse.quote(name), master)
    matches = [x["id"] for x in results if x.get("clientId") == name]
    if len(matches) != 1:
        raise AssertionError("Disposable Keycloak CI client not found uniquely")
    return matches[0]


def assert_realm_user(user_id, expected_role):
    user = request("GET", "/users/" + user_id, master)
    if user.get("id") != user_id or not user.get("enabled"):
        raise AssertionError("Expected a distinct enabled disposable CI principal")
    effective = request("GET",
        "/users/" + user_id + "/role-mappings/realm/composite", master)
    if not any(x.get("name") == expected_role for x in effective):
        raise AssertionError("Missing distinct current registrar/reviewer realm role")


if mode == "prepare":
    assert_realm_user(registrar_id, "platform_credential_registrar")
    assert_realm_user(reviewer_id, "platform_approver")
    read_client = client_id("temporalmark-mfa-directory-checker")
    rm_client = client_id("realm-management")
    service_account = request("GET", "/clients/" + read_client + "/service-account-user", master)
    roles = [request("GET", "/clients/" + rm_client + "/roles/" + role, master)
             for role in ("view-users", "view-realm", "query-users")]
    request("POST", "/users/" + service_account["id"] +
            "/role-mappings/clients/" + rm_client, master, roles)

    # Verify that the actual least-privileged service account can read the
    # CURRENT effective role. No manage-users/realm-admin grant is issued.
    directory_token = form(origin + "/realms/" + realm +
        "/protocol/openid-connect/token", {
            "client_id": "temporalmark-mfa-directory-checker",
            "client_secret": "local-mfa-directory-only",
            "grant_type": "client_credentials"
        })["access_token"]
    for user_id, role in [(registrar_id, "platform_credential_registrar"),
                          (reviewer_id, "platform_approver")]:
        user = request("GET", "/users/" + user_id, directory_token)
        mapped = request("GET", "/users/" + user_id +
                         "/role-mappings/realm/composite", directory_token)
        if not user.get("enabled") or not any(x.get("name") == role for x in mapped):
            raise AssertionError("Read-only directory service denied a required role")
    print("Disposable MFA registrar/reviewer directory read-only fixture ready (no SQL access).")

elif mode == "remove-registrar-role":
    role = request("GET", "/roles/platform_credential_registrar", master)
    request("DELETE", "/users/" + registrar_id + "/role-mappings/realm", master, [role])
    mapped = request("GET", "/users/" + registrar_id +
                     "/role-mappings/realm/composite", master)
    if any(x.get("name") == "platform_credential_registrar" for x in mapped):
        raise AssertionError("Current registrar role was not removed")
    print("Disposable registrar current realm role revoked; old JWT must fail.")

elif mode == "restore-registrar-role":
    role = request("GET", "/roles/platform_credential_registrar", master)
    request("POST", "/users/" + registrar_id + "/role-mappings/realm", master, [role])
    assert_realm_user(registrar_id, "platform_credential_registrar")
    print("Disposable registrar role restored solely to isolate later account-disable test.")

else:
    user = request("GET", "/users/" + registrar_id, master)
    user["enabled"] = False
    request("PUT", "/users/" + registrar_id, master, user)
    current = request("GET", "/users/" + registrar_id, master)
    if current.get("enabled") is not False:
        raise AssertionError("Disposable registrar account was not disabled")
    print("Disposable registrar disabled; old JWT must fail.")
