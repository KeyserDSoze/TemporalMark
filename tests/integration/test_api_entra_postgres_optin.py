"""ADR 0100 / #134: source contract for explicitly selected API Entra SQL mode.

The real .NET offline xUnit suite validates the constructor and bad inputs.
This source-policy test additionally proves the API actually selects the mode,
never binds HTTP before the privilege check and retains the on-prem default.
Azure Terraform and CI do not deploy or create SQL roles.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
API = ROOT / "src/backend/applications/TemporalMark.Api"
INFRA = ROOT / "src/backend/infrastructures/TemporalMark.Infrastructure/Postgres"


class ApiEntraPostgresModeSourceTests(unittest.TestCase):
    def test_api_has_explicit_optin_with_unchanged_default_password_connection(self):
        code = (API / "Program.cs").read_text()
        self.assertIn('builder.Configuration["RegistryPostgres:AuthenticationMode"]', code)
        self.assertIn('"ContainerAppsEntraCandidate"', code)
        self.assertIn('"Password"', code)
        self.assertIn("NpgsqlDataSource.Create(connectionString)", code)
        self.assertIn("ContainerAppsEntraApiRegistryCandidate.Create(", code)
        self.assertIn("builder.Environment.IsProduction()", code)
        self.assertIn("RegistryPostgres:ExpectedRuntimeLogin", code)
        self.assertIn("RegistryPostgres:UserAssignedClientId", code)
        # A typo/unknown mode must NOT silently use a SQL password connection.
        self.assertIn("Unsupported PostgreSQL authentication mode", code)

    def test_aca_runtime_env_is_platform_owned_not_supplied_via_appsettings(self):
        code = (API / "Program.cs").read_text()
        self.assertIn('Environment.GetEnvironmentVariable("IDENTITY_ENDPOINT")', code)
        self.assertIn('Environment.GetEnvironmentVariable("IDENTITY_HEADER")', code)
        for name in ("appsettings.json", "appsettings.Development.json"):
            settings = (API / name).read_text()
            self.assertNotIn("IDENTITY_HEADER", settings)
            self.assertNotIn("IDENTITY_ENDPOINT", settings)
            self.assertNotIn("UserAssignedClientId", settings)
            self.assertNotIn("ContainerAppsEntraCandidate", settings)

    def test_azure_mode_verifies_real_sql_privileges_before_listening(self):
        code = (API / "Program.cs").read_text()
        self.assertIn("VerifyAtStartupAsync(", code)
        self.assertIn("ApplicationStopped.Register(", code)
        self.assertIn("new CancellationTokenSource(TimeSpan.FromSeconds(", code)
        self.assertIn("Registry PostgreSQL Entra startup denied", code)
        self.assertLess(code.index("VerifyAtStartupAsync("), code.index("app.Run();"))
        # The preflight must not be called within an HTTP route or on request.
        self.assertLess(code.index("VerifyAtStartupAsync("), code.index('app.MapHealthChecks("/healthz")'))

    def test_data_source_helper_calls_existing_both_auth_candidates_and_sql_preflight(self):
        source = (INFRA / "ContainerAppsEntraApiRegistryCandidate.cs").read_text()
        self.assertIn("ContainerAppsPostgresManagedIdentityCandidate.Create(", source)
        self.assertIn("EntraPostgresDataSourceCandidate.Create(", source)
        self.assertIn("PostgresRuntimePrivilegePreflight.VerifyAsync(", source)
        self.assertIn("await DataSource.OpenConnectionAsync(", source)
        self.assertIn("await using", source)
        self.assertNotIn("NpgsqlDataSource.Create(", source)
        self.assertNotIn("DefaultAzureCredential", source)
        self.assertNotIn("PgaadAuth", source)
        self.assertNotRegex(source, re.compile(r'(?im)^\\s*(?:GRANT|ALTER ROLE|CREATE ROLE)\\s+'))

    def test_old_azure_stack_and_local_compose_do_not_activate_candidate(self):
        azure = (ROOT / "infra/azure/main.tf").read_text()
        compose = (ROOT / "docker/compose.yml").read_text()
        for data in (azure, compose):
            self.assertNotIn("ContainerAppsEntraCandidate", data)
            self.assertNotIn("RegistryPostgres__AuthenticationMode", data)
        # Existing Terraform admin-password risk remains explicitly open.
        self.assertIn("administrator_password        = var.postgres_password", azure)
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("test_api_entra_postgres_optin.py", workflow)
        self.assertNotRegex(workflow, r"terraform\\s+apply\\b")


if __name__ == "__main__":
    unittest.main()
