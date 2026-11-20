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
  registry_connection_secret_uri   = "https://tmciregistryvault.vault.azure.net/secrets/registry-connection/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  registry_connection_key_vault_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tm-ci-kv-rg/providers/Microsoft.KeyVault/vaults/tmciregistryvault"
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


# Keep Blob traffic off public network. We deliberately check known plan
# attributes, not Azure-assigned IDs unknown in mocked provider plans.
run "evidence_private_blob_link_and_dns_are_in_the_vnet" {
  command = plan

  assert {
    condition     = length(azurerm_subnet.evidence_private_endpoint.address_prefixes) == 1 && azurerm_subnet.evidence_private_endpoint.address_prefixes[0] == "10.40.3.0/24"
    error_message = "Blob Private Endpoint must use its own VNet subnet, not delegated ACA/PostgreSQL subnets."
  }
  assert {
    condition     = azurerm_private_dns_zone.evidence_blob.name == "privatelink.blob.core.windows.net"
    error_message = "Blob endpoint must use the Microsoft-recommended private DNS zone."
  }
  assert {
    condition     = azurerm_private_dns_zone_virtual_network_link.evidence_blob.name == "blob-evidence-vnet"
    error_message = "Blob private DNS must be linked to the application VNet."
  }
  assert {
    condition     = azurerm_private_endpoint.evidence_blob.name == "${var.prefix}-evidence-blob-pe"
    error_message = "Evidence Blob must have a dedicated private endpoint."
  }
  assert {
    condition     = length(azurerm_private_endpoint.evidence_blob.private_service_connection[0].subresource_names) == 1 && azurerm_private_endpoint.evidence_blob.private_service_connection[0].subresource_names[0] == "blob"
    error_message = "Private endpoint must connect specifically to the Blob subservice."
  }
  assert {
    condition     = azurerm_private_endpoint.evidence_blob.private_service_connection[0].is_manual_connection == false
    error_message = "Blob Private Endpoint must connect to the owned account without an unapproved manual connection."
  }
  assert {
    condition     = azurerm_private_endpoint.evidence_blob.private_dns_zone_group[0].name == "evidence-blob-private-dns"
    error_message = "Blob Private Endpoint must be configured with a private DNS zone group."
  }
}
