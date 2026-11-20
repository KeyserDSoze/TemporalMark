# #127 / ADR 0094 — RED-FIRST *real* mocked AzureRM plan: reject direct
# database connection string as Container Apps secret value.
# No Azure subscription, real credential, secret content or resource apply.
mock_provider "azurerm" {}

variables {
  subscription_id                  = "00000000-0000-0000-0000-000000000000"
  prefix                           = "tm-ci-kv"
  location                         = "westeurope"
  storage_account_name             = "tmcikvsecret"
  oidc_authority                   = "https://id.example.org/realms/ci"
  postgres_password                = "CI-FAKE-DO-NOT-DEPLOY"
  registry_connection_secret_uri   = "https://tmciregistryvault.vault.azure.net/secrets/registry-connection/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  registry_connection_key_vault_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tm-ci-kv-rg/providers/Microsoft.KeyVault/vaults/tmciregistryvault"
  api_image                        = "registry.example.invalid/temporalmark/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  web_image                        = "registry.example.invalid/temporalmark/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}

run "api_db_secret_uses_only_key_vault_reference" {
  command = plan
  assert {
    condition     = one(azurerm_container_app.api.secret).key_vault_secret_id != null && one(azurerm_container_app.api.secret).value == null
    error_message = "API DB connection must be a Key Vault secret reference; a direct secret.value leaks into Terraform state."
  }
}

# Additional GREEN cases independently test the exact simulated plan and
# variable/precondition denials. Unknown Azure-assigned IDs are not compared.
run "api_uses_bootstrapped_uai_and_vault_scoped_read_only_role" {
  command = plan
  assert {
    condition     = one(azurerm_container_app.api.secret).name == "registry-connection" && one(azurerm_container_app.api.secret).key_vault_secret_id == var.registry_connection_secret_uri && one(azurerm_container_app.api.secret).value == null
    error_message = "Registry connection must be an exact Key Vault URI-only app secret."
  }
  assert {
    condition     = azurerm_container_app.api.identity[0].type == "SystemAssigned, UserAssigned" && length(azurerm_container_app.api.identity[0].identity_ids) == 1
    error_message = "Keep system-assigned Blob identity, and add exactly one user-assigned secret bootstrap identity."
  }
  assert {
    condition     = azurerm_role_assignment.api_registry_secret_reader.role_definition_name == "Key Vault Secrets User" && azurerm_role_assignment.api_registry_secret_reader.scope == var.registry_connection_key_vault_id
    error_message = "Registry managed identity requires only Key Vault Secrets User on the externally approved Key Vault."
  }
  assert {
    condition     = azurerm_role_assignment.api_evidence_writer.role_definition_name == "Storage Blob Data Contributor"
    error_message = "The existing evidence Blob system-assigned identity role must remain."
  }
}

run "reject_http_key_vault_secret_uri" {
  command = plan
  variables {
    registry_connection_secret_uri = "http://tmciregistryvault.vault.azure.net/secrets/registry-connection/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
  expect_failures = [var.registry_connection_secret_uri]
}

run "reject_key_vault_uri_unversioned" {
  command = plan
  variables {
    registry_connection_secret_uri = "https://tmciregistryvault.vault.azure.net/secrets/registry-connection"
  }
  expect_failures = [var.registry_connection_secret_uri]
}

run "reject_key_vault_uri_query" {
  command = plan
  variables {
    registry_connection_secret_uri = "https://tmciregistryvault.vault.azure.net/secrets/registry-connection/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?token=test"
  }
  expect_failures = [var.registry_connection_secret_uri]
}

run "reject_key_vault_uri_userinfo" {
  command = plan
  variables {
    registry_connection_secret_uri = "https://admin:password@tmciregistryvault.vault.azure.net/secrets/registry-connection/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
  expect_failures = [var.registry_connection_secret_uri]
}

run "reject_key_vault_uri_unapproved_host" {
  command = plan
  variables {
    registry_connection_secret_uri = "https://tmciregistryvault.example.net/secrets/registry-connection/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
  expect_failures = [var.registry_connection_secret_uri]
}

run "reject_key_vault_uri_nonhex_version" {
  command = plan
  variables {
    registry_connection_secret_uri = "https://tmciregistryvault.vault.azure.net/secrets/registry-connection/latest"
  }
  expect_failures = [var.registry_connection_secret_uri]
}

run "reject_invalid_key_vault_arm_id" {
  command = plan
  variables {
    registry_connection_key_vault_id = "/subscriptions/unknown/resourceGroups/test/providers/Microsoft.KeyVault/vaults/test"
  }
  expect_failures = [var.registry_connection_key_vault_id]
}

run "reject_secret_uri_different_vault_than_rbac_scope" {
  command = plan
  variables {
    registry_connection_secret_uri = "https://othervaultapproved.vault.azure.net/secrets/registry-connection/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
  expect_failures = [azurerm_container_app.api]
}
