# ADR 0095 / #129: RED-first mocked AzureRM plan assertions for an
# ISOLATED new-server candidate. This root is NOT instantiated by main Azure.
# No real Azure subscription, SQL/Entra tokens, remote state or resource apply.
mock_provider "azurerm" {}

variables {
  subscription_id        = "11111111-1111-4111-8111-111111111111"
  resource_group_name    = "tm-ci-entra-rg"
  location               = "westeurope"
  candidate_server_name  = "tm-ci-entra-candidate"
  postgres_subnet_id     = "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/tm-ci-entra-rg/providers/Microsoft.Network/virtualNetworks/tm-ci-entra-vnet/subnets/postgres"
  private_dns_zone_id    = "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/tm-ci-entra-rg/providers/Microsoft.Network/privateDnsZones/tm-ci-entra.postgres.database.azure.com"
  entra_tenant_id        = "22222222-2222-4222-8222-222222222222"
  entra_admin_group_id   = "33333333-3333-4333-8333-333333333333"
  entra_admin_group_name = "tm-ci-db-admin-group"
}

run "isolated_pg_candidate_must_be_entra_only_passwordless_and_private" {
  command = plan
  assert {
    condition     = one(azurerm_postgresql_flexible_server.registry_candidate.authentication).active_directory_auth_enabled == true
    error_message = "Candidate PostgreSQL must explicitly enable Microsoft Entra auth."
  }
  assert {
    condition     = one(azurerm_postgresql_flexible_server.registry_candidate.authentication).password_auth_enabled == false
    error_message = "Candidate PostgreSQL must explicitly DISABLE password authentication."
  }
  assert {
    condition     = one(azurerm_postgresql_flexible_server.registry_candidate.authentication).tenant_id == var.entra_tenant_id
    error_message = "Candidate Entra tenant ID must be explicitly pinned to approved input."
  }
  # Provider-computed administrator_login is UNKNOWN in a mocked plan.
  # A separate mandatory Python source-policy test asserts no password/admin
  # login attributes or variables are declared, rather than inventing null.
  assert {
    condition     = azurerm_postgresql_flexible_server.registry_candidate.public_network_access_enabled == false
    error_message = "Candidate PostgreSQL must explicitly deny public network access."
  }
  assert {
    condition     = azurerm_postgresql_flexible_server.registry_candidate.delegated_subnet_id == var.postgres_subnet_id && azurerm_postgresql_flexible_server.registry_candidate.private_dns_zone_id == var.private_dns_zone_id
    error_message = "Candidate PostgreSQL must attach only to the approved private delegated subnet and DNS zone."
  }
  assert {
    condition     = azurerm_postgresql_flexible_server.registry_candidate.name == var.candidate_server_name && azurerm_postgresql_flexible_server.registry_candidate.version == "17"
    error_message = "Candidate must be a distinctly named PostgreSQL 17 test server."
  }
  assert {
    condition     = azurerm_postgresql_flexible_server_database.registry_candidate.name == "temporalmark_candidate"
    error_message = "Candidate database must not collide with the active registry database."
  }
}

run "reviewed_entra_group_is_separate_administrator" {
  command = plan
  assert {
    condition     = azurerm_postgresql_flexible_server_active_directory_administrator.registry_candidate.principal_type == "Group"
    error_message = "Candidate administrator must be a separately approved Microsoft Entra group, not an individual or generic application."
  }
  assert {
    condition     = azurerm_postgresql_flexible_server_active_directory_administrator.registry_candidate.object_id == var.entra_admin_group_id && azurerm_postgresql_flexible_server_active_directory_administrator.registry_candidate.tenant_id == var.entra_tenant_id
    error_message = "Group object ID and tenant must match approved inputs."
  }
  assert {
    condition     = azurerm_postgresql_flexible_server_active_directory_administrator.registry_candidate.principal_name == var.entra_admin_group_name && azurerm_postgresql_flexible_server_active_directory_administrator.registry_candidate.server_name == var.candidate_server_name
    error_message = "Candidate admin must be tied to correct new server and exact group name."
  }
}

run "reject_existing_server_name_without_candidate_suffix" {
  command = plan
  variables {
    candidate_server_name = "temporalmark-pg"
  }
  expect_failures = [var.candidate_server_name]
}
run "reject_uppercase_or_bad_candidate_server_name" {
  command = plan
  variables {
    candidate_server_name = "TM-CI-ENTRA-CANDIDATE"
  }
  expect_failures = [var.candidate_server_name]
}
run "reject_missing_subscription" {
  command = plan
  variables {
    subscription_id = ""
  }
  expect_failures = [var.subscription_id]
}
run "reject_invalid_entra_tenant" {
  command = plan
  variables {
    entra_tenant_id = "invalid-tenant"
  }
  expect_failures = [var.entra_tenant_id]
}
run "reject_invalid_group_object_id" {
  command = plan
  variables {
    entra_admin_group_id = "invalid-group"
  }
  expect_failures = [var.entra_admin_group_id]
}
run "reject_unapproved_group_label" {
  command = plan
  variables {
    entra_admin_group_name = "not a canonical group"
  }
  expect_failures = [var.entra_admin_group_name]
}
run "reject_wrong_postgres_subnet_name" {
  command = plan
  variables {
    postgres_subnet_id = "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/tm-ci-entra-rg/providers/Microsoft.Network/virtualNetworks/tm-ci-entra-vnet/subnets/apps"
  }
  expect_failures = [var.postgres_subnet_id]
}
run "reject_non_pg_private_dns_zone" {
  command = plan
  variables {
    private_dns_zone_id = "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/tm-ci-entra-rg/providers/Microsoft.Network/privateDnsZones/privatelink.blob.core.windows.net"
  }
  expect_failures = [var.private_dns_zone_id]
}
run "reject_subnet_in_different_subscription" {
  command = plan
  variables {
    postgres_subnet_id = "/subscriptions/99999999-9999-4999-8999-999999999999/resourceGroups/tm-ci-entra-rg/providers/Microsoft.Network/virtualNetworks/tm-ci-entra-vnet/subnets/postgres"
  }
  expect_failures = [azurerm_postgresql_flexible_server.registry_candidate]
}
run "reject_dns_zone_in_different_resource_group" {
  command = plan
  variables {
    private_dns_zone_id = "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/unapproved-rg/providers/Microsoft.Network/privateDnsZones/tm-ci-entra.postgres.database.azure.com"
  }
  expect_failures = [azurerm_postgresql_flexible_server.registry_candidate]
}
run "reject_same_entra_admin_and_tenant_id" {
  command = plan
  variables {
    entra_admin_group_id = "22222222-2222-4222-8222-222222222222"
  }
  expect_failures = [azurerm_postgresql_flexible_server_active_directory_administrator.registry_candidate]
}
