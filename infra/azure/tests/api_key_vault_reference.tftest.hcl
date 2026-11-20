# #127 / ADR 0094 — RED-FIRST *real* mocked AzureRM plan: reject direct
# database connection string as Container Apps secret value.
# No Azure subscription, real credential, secret content or resource apply.
mock_provider "azurerm" {}

variables {
  subscription_id            = "00000000-0000-0000-0000-000000000000"
  prefix                     = "tm-ci-kv"
  location                   = "westeurope"
  storage_account_name       = "tmcikvsecret"
  oidc_authority             = "https://id.example.org/realms/ci"
  postgres_password          = "CI-FAKE-DO-NOT-DEPLOY"
  registry_connection_string = "CI-FAKE-DO-NOT-DEPLOY"
  api_image                  = "registry.example.invalid/temporalmark/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  web_image                  = "registry.example.invalid/temporalmark/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}

run "api_db_secret_uses_only_key_vault_reference" {
  command = plan
  assert {
    condition     = azurerm_container_app.api.secret[0].key_vault_secret_id != null && azurerm_container_app.api.secret[0].value == null
    error_message = "API DB connection must be a Key Vault secret reference; a direct secret.value leaks into Terraform state."
  }
}
