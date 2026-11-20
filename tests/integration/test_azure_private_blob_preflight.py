"""RED-first #126: Azure CLI private Blob live-preflight contract. No Azure account used."""
import copy
import importlib.util
import pathlib
import subprocess
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "azure_private_blob_preflight.py"
spec = importlib.util.spec_from_file_location("azure_private_blob_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)

SUB = "00000000-0000-0000-0000-000000000000"
RG = "tm-preflight-rg"
ACCOUNT = "tmprivateevidence"
ENDPOINT = "tm-preflight-evidence-blob-pe"
ACCOUNT_ID = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Storage/storageAccounts/{ACCOUNT}"
NIC_ID = f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Network/networkInterfaces/private-blob-nic"
PE_IP = "10.40.3.8"


def fixtures():
    return {
        "account": {"id": SUB},
        "storage": {
            "id": ACCOUNT_ID, "name": ACCOUNT, "publicNetworkAccess": "Disabled",
            "allowBlobPublicAccess": False, "allowSharedKeyAccess": False,
            "enableHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2",
        },
        "pe": {
            "provisioningState": "Succeeded",
            "subnet": {"id": f"/subscriptions/{SUB}/resourceGroups/{RG}/providers/Microsoft.Network/virtualNetworks/tm-vnet/subnets/blob-private-endpoints"},
            "privateLinkServiceConnections": [{
                "privateLinkServiceId": ACCOUNT_ID, "groupIds": ["blob"],
                "privateLinkServiceConnectionState": {"status": "Approved"},
            }],
            "manualPrivateLinkServiceConnections": [],
            "networkInterfaces": [{"id": NIC_ID}],
        },
        "nic": {"ipConfigurations": [{"privateIPAddress": PE_IP}]},
    }


class Harness:
    def __init__(self, overrides=None, dns=None, environment=None, deny_list=False):
        self.data = fixtures()
        if overrides:
            for key, value in overrides.items():
                self.data[key] = value
        self.dns = [PE_IP] if dns is None else dns
        self.environment = {} if environment is None else environment
        self.deny_list = deny_list
        self.calls = []

    def json(self, argv):
        self.calls.append(tuple(argv))
        key = {
            ("account", "show"): "account",
            ("storage", "account", "show"): "storage",
            ("network", "private-endpoint", "show"): "pe",
            ("network", "nic", "show"): "nic",
        }
        for prefix, name in key.items():
            if tuple(argv[:len(prefix)]) == prefix:
                return copy.deepcopy(self.data[name])
        raise AssertionError(f"unexpected command type: {argv[:3]}")

    def list_blobs(self, argv):
        self.calls.append(tuple(argv))
        if self.deny_list:
            raise preflight.PreflightError("Azure CLI read-only Blob LIST failed")

    def lookup(self, hostname):
        self.calls.append(("DNS", hostname))
        return self.dns

    def check(self):
        preflight.check_private_blob(
            SUB, RG, ACCOUNT, ENDPOINT,
            run_json=self.json, run_list=self.list_blobs,
            resolve_dns=self.lookup, environment=self.environment,
        )


class PrivateBlobPreflightTests(unittest.TestCase):
    def test_happy_path_is_private_account_approved_pe_exact_dns_and_aad_read_only(self):
        h = Harness()
        h.check()
        self.assertIn(("DNS", f"{ACCOUNT}.blob.core.windows.net"), h.calls)
        commands = [list(c) for c in h.calls if c[0] != "DNS"]
        self.assertEqual(5, len(commands))
        for command in commands:
            self.assertIn("--subscription", command)
            self.assertIn(SUB, command)
            self.assertNotIn("--account-key", command)
            self.assertNotIn("--sas-token", command)
            self.assertNotIn("--debug", command)
        listing = commands[-1]
        self.assertEqual(["storage", "blob", "list"], listing[:3])
        self.assertIn("--auth-mode", listing)
        self.assertEqual("login", listing[listing.index("--auth-mode") + 1])
        self.assertEqual("timestamp-evidence", listing[listing.index("--container-name") + 1])
        self.assertEqual("1", listing[listing.index("--num-results") + 1])
        self.assertNotIn("upload", listing)
        self.assertNotIn("delete", listing)

    def test_wrong_subscription_is_denied_before_storage_read(self):
        h = Harness({"account": {"id": "11111111-1111-1111-1111-111111111111"}})
        with self.assertRaises(preflight.PreflightError):
            h.check()
        self.assertEqual(1, len(h.calls))

    def test_missing_or_insecure_storage_properties_fail_closed(self):
        bad = (
            ("publicNetworkAccess", "Enabled"),
            ("publicNetworkAccess", None),
            ("allowBlobPublicAccess", True),
            ("allowBlobPublicAccess", None),
            ("allowSharedKeyAccess", True),
            ("enableHttpsTrafficOnly", False),
            ("minimumTlsVersion", "TLS1_0"),
            ("minimumTlsVersion", None),
            ("id", ACCOUNT_ID.replace(ACCOUNT, "otheraccount")),
        )
        for field, value in bad:
            with self.subTest(field=field, value=value):
                storage = fixtures()["storage"]
                storage[field] = value
                h = Harness({"storage": storage})
                with self.assertRaises(preflight.PreflightError):
                    h.check()
                self.assertFalse(any(c[:3] == ("storage", "blob", "list") for c in h.calls))

    def test_connection_status_group_target_subnet_nic_and_provisioning_must_match(self):
        base = fixtures()["pe"]
        bad = []
        for field, value in (("provisioningState", "Updating"), ("networkInterfaces", []),
                             ("manualPrivateLinkServiceConnections", [{"id": "unexpected"}]),
                             ("privateLinkServiceConnections", []),
                             ("privateLinkServiceConnections", base["privateLinkServiceConnections"] * 2),
                             ("subnet", {"id": "/unexpected/subnets/apps"})):
            x = copy.deepcopy(base); x[field] = value; bad.append(x)
        for field, value in (
            ("privateLinkServiceId", ACCOUNT_ID.replace(ACCOUNT, "otheraccount")),
            ("groupIds", ["file"]),
            ("groupIds", ["blob", "file"]),
            ("privateLinkServiceConnectionState", {"status": "Pending"}),
        ):
            x = copy.deepcopy(base)
            x["privateLinkServiceConnections"][0][field] = value
            bad.append(x)
        for i, pe in enumerate(bad):
            with self.subTest(case=i):
                h = Harness({"pe": pe})
                with self.assertRaises(preflight.PreflightError):
                    h.check()
                self.assertFalse(any(c[:3] == ("storage", "blob", "list") for c in h.calls))

    def test_private_nic_ip_must_be_unambiguous_and_expected_subnet(self):
        for config in ([], [{"privateIPAddress": "8.8.8.8"}],
                       [{"privateIPAddress": "10.40.3.8"}, {"privateIPAddress": "10.40.3.9"}],
                       [{"privateIPAddress": None}]):
            with self.subTest(config=config):
                h = Harness({"nic": {"ipConfigurations": config}})
                with self.assertRaises(preflight.PreflightError):
                    h.check()

    def test_dns_fail_closed_for_public_extra_wrong_or_empty_addresses(self):
        for resolved in ([], ["1.1.1.1"], [PE_IP, "1.1.1.1"], ["10.40.3.9"], ["not-an-ip"]):
            with self.subTest(resolved=resolved):
                h = Harness(dns=resolved)
                with self.assertRaises(preflight.PreflightError):
                    h.check()
                self.assertFalse(any(c[:3] == ("storage", "blob", "list") for c in h.calls))

    def test_list_denied_propagates_as_failure_not_success(self):
        with self.assertRaises(preflight.PreflightError):
            Harness(deny_list=True).check()

    def test_proxy_env_blocks_direct_path_claim_before_network(self):
        for key in ("HTTP_PROXY", "https_proxy", "ALL_PROXY"):
            with self.subTest(key=key):
                h = Harness(environment={key: "http://proxy.example.invalid"})
                with self.assertRaises(preflight.PreflightError):
                    h.check()
                self.assertEqual([], h.calls)

    def test_invalid_cli_identifiers_are_rejected_before_az(self):
        for args in (
            ("no", RG, ACCOUNT, ENDPOINT),
            (SUB, "../unsafe", ACCOUNT, ENDPOINT),
            (SUB, RG, "UPPER", ENDPOINT),
            (SUB, RG, ACCOUNT, "-invalid"),
        ):
            with self.subTest(args=args):
                h = Harness()
                with self.assertRaises(preflight.PreflightError):
                    preflight.check_private_blob(*args, run_json=h.json, run_list=h.list_blobs,
                                                 resolve_dns=h.lookup, environment={})
                self.assertEqual([], h.calls)

    def test_azure_cli_failures_hide_arbitrary_stdout_stderr(self):
        error = subprocess.CalledProcessError(1, ["az"], output="secret-JWT", stderr="secret-account-key")
        with mock.patch.object(preflight.subprocess, "run", side_effect=error):
            with self.assertRaises(preflight.PreflightError) as caught:
                preflight.run_az_json(["account", "show", "--subscription", SUB])
        self.assertNotIn("secret-JWT", str(caught.exception))
        self.assertNotIn("secret-account-key", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
