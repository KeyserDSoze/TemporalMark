"""#129 / ADR 0095: source policy for facts that Terraform mock plans cannot know.

Plan-time computed administrator_login is UNKNOWN with mock_provider azurerm.
Never assert it is null; reject any source declaration of SQL credentials.
"""
import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
CANDIDATE = ROOT / "infra" / "azure" / "candidates" / "entra_postgres"


class EntraCandidateSourcePolicyTests(unittest.TestCase):
    def test_new_candidate_root_is_not_instantiated_by_existing_azure_stack(self):
        current = (ROOT / "infra" / "azure" / "main.tf").read_text()
        self.assertNotIn('source = "./candidates/entra_postgres"', current)
        self.assertNotIn('source = "candidates/entra_postgres"', current)
        self.assertNotIn('module "entra_postgres"', current)
        self.assertIn('administrator_password        = var.postgres_password', current)
        # Existing SQL password risk remains OPEN and must not be misreported as fixed.

    def test_candidate_has_no_sql_password_or_admin_login_input_or_assignment(self):
        sources = "\n".join((CANDIDATE / p).read_text()
                            for p in ("main.tf", "variables.tf", "versions.tf"))
        forbidden = (
            r'^\s*administrator_login\s*=',
            r'^\s*administrator_password(?:_wo|_wo_version)?\s*=',
            r'^\s*variable\s+"(?:postgres_password|postgres_admin|administrator_password|administrator_login|registry_connection_string)"',
            r'^\s*data\s+"azurerm_key_vault_secret"',
            r'^\s*resource\s+"azurerm_key_vault_secret"',
        )
        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(sources, re.compile(pattern, re.MULTILINE))
        self.assertIn('password_auth_enabled         = false', sources)
        self.assertIn('active_directory_auth_enabled = true', sources)
        self.assertIn('public_network_access_enabled = false', sources)

    def test_candidate_has_private_server_group_admin_and_ordered_candidate_db(self):
        source = (CANDIDATE / "main.tf").read_text()
        for kind in (
            "azurerm_postgresql_flexible_server",
            "azurerm_postgresql_flexible_server_active_directory_administrator",
            "azurerm_postgresql_flexible_server_database",
        ):
            with self.subTest(resource=kind):
                self.assertEqual(
                    1, len(re.findall(r'^resource "' + re.escape(kind) + r'" "registry_candidate"\s*\{', source, re.MULTILINE))
                )
        self.assertIn('principal_type      = "Group"', source)
        self.assertIn('prevent_destroy = true', source)
        self.assertIn('depends_on = [azurerm_postgresql_flexible_server_active_directory_administrator.registry_candidate]', source)
        self.assertIn('name      = "temporalmark_candidate"', source)
        self.assertNotIn('resource "azurerm_resource_group"', source)

    def test_candidate_is_only_mock_plan_tested_in_ci_without_apply(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("terraform -chdir=infra/azure/candidates/entra_postgres init -backend=false", workflow)
        self.assertIn(
            "terraform -chdir=infra/azure/candidates/entra_postgres test -no-color -filter=tests/entra_only_candidate.tftest.hcl",
            workflow,
        )
        self.assertNotRegex(workflow, r'terraform\s+-chdir=infra/azure/candidates/entra_postgres\s+apply\b')


    def test_scoped_runtime_identity_is_separate_non_admin_and_not_auto_attached(self):
        source = (CANDIDATE / "main.tf").read_text()
        variables = (CANDIDATE / "variables.tf").read_text()
        self.assertEqual(
            1, len(re.findall(
                r'^resource "azurerm_user_assigned_identity" "postgres_runtime_candidate"\\s*\\{',
                source, re.MULTILINE,
            )),
            "Exactly one isolated PostgreSQL runtime UAI must be declared",
        )
        self.assertIn('variable "postgres_runtime_identity_name" {', variables)
        self.assertIn('name                = var.postgres_runtime_identity_name', source)
        self.assertIn('resource_group_name = var.resource_group_name', source)
        self.assertIn('location            = var.location', source)
        self.assertIn('tags                = local.candidate_tags', source)
        # Source checks complement mock plan; lifecycle is not provable by
        # provider plan values. Never pretend computed IDs are real on CI.
        identity_block = source.partition(
            'resource "azurerm_user_assigned_identity" "postgres_runtime_candidate" {'
        )[2].split("\\nresource ", 1)[0]
        self.assertIn('prevent_destroy = true', identity_block)
        self.assertIn('var.entra_admin_group_name', identity_block)
        self.assertNotIn('principal_type = "ServicePrincipal"', identity_block)

    def test_candidate_identity_outputs_are_only_nonsecret_metadata(self):
        outputs = (CANDIDATE / "outputs.tf").read_text()
        expected = {
            'postgres_runtime_identity_resource_id': 'id',
            'postgres_runtime_identity_client_id': 'client_id',
            'postgres_runtime_identity_principal_id': 'principal_id',
        }
        for name, attribute in expected.items():
            with self.subTest(output=name):
                self.assertRegex(
                    outputs,
                    re.compile(
                        r'output "' + re.escape(name) + r'"\\s*\\{[^}]*'
                        r'value\\s*=\\s*azurerm_user_assigned_identity'
                        r'\\.postgres_runtime_candidate\\.' + attribute + r'\\b',
                        re.MULTILINE | re.DOTALL,
                    ),
                )
        self.assertEqual(3, outputs.count('output "'))
        self.assertNotRegex(outputs, r'(?im)^\\s*(sensitive|password|secret|token)\\s*=')

    def test_runtime_identity_candidate_never_auto_attaches_or_grants_sql_or_rbac(self):
        sources = "\\n".join((CANDIDATE / p).read_text()
                            for p in ("main.tf", "variables.tf", "versions.tf"))
        for banned in (
            r'^\\s*resource "azurerm_container_app"',
            r'^\\s*resource "azurerm_role_assignment"',
            r'^\\s*resource "azurerm_postgresql_flexible_server_active_directory_administrator" "postgres_runtime_candidate"',
            r'^\\s*resource "null_resource"',
            r'^\\s*resource "terraform_data"',
            r'^\\s*data "external"',
            r'^\\s*provisioner "local-exec"',
            r'pgaadauth_create_principal\\s*\\(',
        ):
            with self.subTest(pattern=banned):
                self.assertNotRegex(sources, re.compile(banned, re.MULTILINE))


if __name__ == "__main__":
    unittest.main()
