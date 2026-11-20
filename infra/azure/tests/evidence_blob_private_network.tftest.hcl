# TDD RED-FIRST #125. Mocked AzureRM resource plans; no Azure login, real
# customer data or resource apply. The account is private at container/RBAC
# level but must also explicitly deny its public NETWORK endpoint.
mock_provider "azurerm" {}

variables {
  subscription_id            = "00000000-0000-0000-0000-000000000000"
  prefix                     = "tm-ci-evidence"
  location                   = "westeurope"
  storage_account_name       = "tmcievidenceprivate"
  oidc_authority             = "https://identity.example.org/realms/ci"
  postgres_password          = "CI-FAKE-DO-NOT-DEPLOY"
  registry_connection_string = "CI-FAKE-DO-NOT-DEPLOY"
  api_image                  = "registry.example.invalid/temporalmark/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  web_image                  = "registry.example.invalid/temporalmark/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}

run "evidence_account_rejects_public_network_and_plaintext" {
  command = plan

  assert {
    condition     = azurerm_storage_account.evidence.public_network_access_enabled == false
    error_message = "Evidence Storage must explicitly deny the public network endpoint, not only anonymous Blob access."
  }
  assert {
    condition     = azurerm_storage_account.evidence.https_traffic_only_enabled == true
    error_message = "Evidence Storage must accept HTTPS transport only."
  }
  assert {
    condition     = azurerm_storage_account.evidence.shared_access_key_enabled == false && azurerm_storage_account.evidence.allow_nested_items_to_be_public == false
    error_message = "Storage Shared Key and anonymous nested-blob access must remain disabled."
  }
  assert {
    condition     = azurerm_storage_account.evidence.min_tls_version == "TLS1_2"
    error_message = "Evidence Storage TLS version must remain at least 1.2."
  }
  assert {
    condition     = azurerm_storage_container.evidence.container_access_type == "private"
    error_message = "Evidence Blob container cannot allow anonymous access."
  }
}
