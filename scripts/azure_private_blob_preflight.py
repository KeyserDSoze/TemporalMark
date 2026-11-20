#!/usr/bin/env python3
"""Read-only, fail-closed Azure private Blob runner preflight (#126, ADR 0093).

Run manually on an authorized VNet-connected runner after an approved deploy.
CI simulates the CLI and DNS only. Never logs Azure CLI stdout or stderr.
"""
import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys

CONTAINER = "timestamp-evidence"
SUBNET = "blob-private-endpoints"
SUBNET_CIDR = ipaddress.ip_network("10.40.3.0/24")
CLI_TIMEOUT_SECONDS = 30


class PreflightError(Exception):
    """Safe-to-print, fixed-text denial; never include Azure CLI output."""


def _require(condition, message):
    if not condition:
        raise PreflightError(message)


def _run_az(argv, output):
    # Neither stderr nor stdout, token values, or arbitrary CLI exception
    # strings may be printed: they can contain bearer tokens or blob names.
    try:
        result = subprocess.run(
            ["az", *argv, "--output", output, "--only-show-errors"],
            capture_output=True, text=True, check=True,
            timeout=CLI_TIMEOUT_SECONDS,
        )
        return result.stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
        raise PreflightError("Azure CLI operation failed; inspect protected runner diagnostics") from None


def run_az_json(argv):
    raw = _run_az(argv, "json")
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        raise PreflightError("Azure CLI returned invalid metadata JSON") from None
    _require(isinstance(parsed, dict), "Azure CLI returned non-object metadata")
    return parsed


def run_az_list(argv):
    # CLI handles a bounded, read-only LIST; never emit object metadata.
    _run_az(argv, "none")


def resolve_private_dns(hostname):
    try:
        addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except OSError:
        raise PreflightError("Private Blob DNS resolution failed") from None
    return [entry[4][0] for entry in addresses]


def _arm_id(value):
    return value.rstrip("/").lower() if isinstance(value, str) else ""


def _single_list(value, reason):
    _require(isinstance(value, list) and len(value) == 1, reason)
    _require(isinstance(value[0], dict), reason)
    return value[0]


def _input_checks(subscription_id, resource_group, storage_account, private_endpoint):
    _require(re.fullmatch(r"[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}", subscription_id) is not None,
             "Invalid subscription ID")
    _require(re.fullmatch(r"[A-Za-z0-9_().-]{1,90}", resource_group) is not None
             and not resource_group.endswith("."), "Invalid resource group")
    _require(re.fullmatch(r"[a-z0-9]{3,24}", storage_account) is not None,
             "Invalid Storage Account name")
    _require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,79}", private_endpoint) is not None,
             "Invalid Private Endpoint name")


def check_private_blob(subscription_id, resource_group, storage_account, private_endpoint,
                       *, run_json=run_az_json, run_list=run_az_list,
                       resolve_dns=resolve_private_dns, environment=None):
    """Fail-closed private-path + runner Entra LIST preflight; no Azure writes."""
    _input_checks(subscription_id, resource_group, storage_account, private_endpoint)

    if environment is None:
        environment = os.environ
    _require(
        not any(name.lower() in ("http_proxy", "https_proxy", "all_proxy") and str(value).strip()
                for name, value in environment.items()),
        "Ambient HTTP(S) proxy detected; direct private path cannot be verified",
    )

    selected = run_json(["account", "show", "--subscription", subscription_id])
    _require(str(selected.get("id", "")).lower() == subscription_id.lower(),
             "Azure CLI selected a different subscription")

    account = run_json([
        "storage", "account", "show", "--subscription", subscription_id,
        "--resource-group", resource_group, "--name", storage_account,
    ])
    account_id = (
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.Storage/storageAccounts/{storage_account}"
    )
    _require(_arm_id(account.get("id")) == _arm_id(account_id),
             "Storage Account identity differs from requested subscription/group/name")
    _require(account.get("publicNetworkAccess") == "Disabled",
             "Storage Account public network access is not explicitly Disabled")
    _require(account.get("allowBlobPublicAccess") is False,
             "Anonymous Blob access is not explicitly disabled")
    _require(account.get("allowSharedKeyAccess") is False,
             "Storage Shared Key access is not explicitly disabled")
    _require(account.get("enableHttpsTrafficOnly") is True,
             "Storage Account HTTPS-only transport is not explicitly enabled")
    _require(account.get("minimumTlsVersion") in ("TLS1_2", "TLS1_3"),
             "Storage Account minimum TLS version is below 1.2 or unknown")

    endpoint = run_json([
        "network", "private-endpoint", "show", "--subscription", subscription_id,
        "--resource-group", resource_group, "--name", private_endpoint,
    ])
    _require(endpoint.get("provisioningState") == "Succeeded",
             "Blob Private Endpoint provisioning has not succeeded")
    subnet_id = _arm_id((endpoint.get("subnet") or {}).get("id"))
    expected_prefix = _arm_id(
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        "/providers/Microsoft.Network/virtualNetworks/"
    )
    _require(subnet_id.startswith(expected_prefix) and subnet_id.endswith("/subnets/" + SUBNET),
             "Blob Private Endpoint subnet differs from the dedicated private subnet")
    _require(endpoint.get("manualPrivateLinkServiceConnections") in (None, []),
             "Unexpected manual Private Endpoint connection")
    conn = _single_list(endpoint.get("privateLinkServiceConnections"),
                        "Private Endpoint must have exactly one Blob service connection")
    _require(_arm_id(conn.get("privateLinkServiceId")) == _arm_id(account_id),
             "Private Endpoint targets a different Storage Account")
    _require(conn.get("groupIds") == ["blob"],
             "Private Endpoint must connect only to Blob")
    _require((conn.get("privateLinkServiceConnectionState") or {}).get("status") == "Approved",
             "Private Endpoint Blob connection is not Approved")

    nic_id = _single_list(endpoint.get("networkInterfaces"),
                          "Private Endpoint must have exactly one NIC").get("id")
    nic_prefix = _arm_id(
        f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"
        "/providers/Microsoft.Network/networkInterfaces/"
    )
    _require(_arm_id(nic_id).startswith(nic_prefix) and len(_arm_id(nic_id)) > len(nic_prefix),
             "Private Endpoint NIC identifier is missing or outside the expected group")
    nic = run_json(["network", "nic", "show", "--subscription", subscription_id, "--ids", nic_id])
    ip_text = _single_list(nic.get("ipConfigurations"),
                           "Private Endpoint NIC must have exactly one IP configuration").get("privateIPAddress")
    try:
        private_ip = ipaddress.ip_address(ip_text)
    except (ValueError, TypeError):
        raise PreflightError("Private Endpoint NIC has no valid private IP") from None
    _require(private_ip.version == 4 and private_ip in SUBNET_CIDR,
             "Private Endpoint NIC IP is outside the dedicated private subnet")

    hostname = f"{storage_account}.blob.core.windows.net"
    try:
        addresses = resolve_dns(hostname)
        resolved = {ipaddress.ip_address(address) for address in addresses}
    except (ValueError, TypeError, OSError, PreflightError):
        raise PreflightError("Private Blob DNS lookup failed or returned invalid addresses") from None
    _require(resolved == {private_ip},
             "Blob hostname DNS does not exclusively resolve to the approved Private Endpoint NIC IP")

    # Read-only operation as CURRENT RUNNER's Entra principal. No Shared Key,
    # SAS, customer blob name, download, write or delete operation.
    run_list([
        "storage", "blob", "list", "--subscription", subscription_id,
        "--account-name", storage_account, "--container-name", CONTAINER,
        "--auth-mode", "login", "--num-results", "1",
    ])


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only private Blob runner preflight (not legal custody verification)")
    parser.add_argument("--subscription-id", required=True)
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--storage-account", required=True)
    parser.add_argument("--private-endpoint", required=True)
    args = parser.parse_args(argv)
    try:
        check_private_blob(args.subscription_id, args.resource_group,
                           args.storage_account, args.private_endpoint)
    except PreflightError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print("PASS: account/PE/NIC/DNS private-path checks and runner Entra read-only Blob LIST succeeded.")
    print("NOT PROVED: app Managed Identity PUT/GET, external public denial, actual WORM or legal qualification.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
