# PREQUALIFICATION CANDIDATE ONLY (#129 / ADR 0095).
# This is a separate Terraform ROOT never instantiated by infra/azure/main.tf.
# DO NOT apply to a live subscription without CAB/role, state and DR approval.
locals {
  expected_resource_scope = lower("/subscriptions/${var.subscription_id}/resourceGroups/${var.resource_group_name}")
  candidate_tags = {
    application = "TemporalMark"
    environment = "disposable-entra-candidate"
    compliance  = "NOT_QUALIFIED"
    auto_deploy = "DENIED"
  }
}

# New server only. Never apply to, import or migrate the existing registry.
# No local SQL password/admin login; Entra token integration in API/migrations
# remains a separate blocker under parent #128.
resource "azurerm_postgresql_flexible_server" "registry_candidate" {
  name                          = var.candidate_server_name
  resource_group_name           = var.resource_group_name
  location                      = var.location
  version                       = "17"
  delegated_subnet_id           = var.postgres_subnet_id
  private_dns_zone_id           = var.private_dns_zone_id
  public_network_access_enabled = false
  storage_mb                    = 32768
  sku_name                      = "B_Standard_B1ms"
  backup_retention_days         = 14
  tags                          = local.candidate_tags

  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = false
    tenant_id                     = var.entra_tenant_id
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = startswith(lower(var.postgres_subnet_id), "${local.expected_resource_scope}/providers/microsoft.network/virtualnetworks/") && endswith(lower(var.postgres_subnet_id), "/subnets/postgres")
      error_message = "Candidate subnet must be the explicit postgres delegated subnet in the requested subscription/resource group."
    }

    precondition {
      condition     = startswith(lower(var.private_dns_zone_id), "${local.expected_resource_scope}/providers/microsoft.network/privatednszones/") && endswith(lower(var.private_dns_zone_id), ".postgres.database.azure.com")
      error_message = "Private PostgreSQL DNS zone must be in the approved subscription/resource group, not a public or Blob DNS zone."
    }
  }
}

# Pre-approved Microsoft Entra GROUP, never an individual SQL login.
# This resource does not attest membership, MFA, human approval or SQL grants.
resource "azurerm_postgresql_flexible_server_active_directory_administrator" "registry_candidate" {
  server_name         = azurerm_postgresql_flexible_server.registry_candidate.name
  resource_group_name = var.resource_group_name
  tenant_id           = var.entra_tenant_id
  object_id           = var.entra_admin_group_id
  principal_name      = var.entra_admin_group_name
  principal_type      = "Group"

  lifecycle {
    precondition {
      condition     = lower(var.entra_admin_group_id) != lower(var.entra_tenant_id)
      error_message = "The Entra admin group object ID must be a distinct approved principal, not the tenant ID."
    }
  }
}

# Candidate is deliberately NOT named temporalmark, to avoid accidentally
# attaching the current application database to a passwordless test server.
# Microsoft notes that DB creation ordering matters for Entra ownership.
resource "azurerm_postgresql_flexible_server_database" "registry_candidate" {
  name      = "temporalmark_candidate"
  server_id = azurerm_postgresql_flexible_server.registry_candidate.id
  charset   = "UTF8"
  collation = "en_US.utf8"

  depends_on = [azurerm_postgresql_flexible_server_active_directory_administrator.registry_candidate]

  lifecycle {
    prevent_destroy = true
  }
}

# Distinct app data-plane identity (#132 / ADR 0098), for a FUTURE approved
# Container Apps attachment and Entra PostgreSQL principal creation.
# Not an Entra administrator, not an Azure SQL grant, not deployed by CI.
# The currently deployed API Blob and Key Vault identities remain untouched.
resource "azurerm_user_assigned_identity" "postgres_runtime_candidate" {
  name                = var.postgres_runtime_identity_name
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = local.candidate_tags

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = lower(var.postgres_runtime_identity_name) != lower(var.entra_admin_group_name) && lower(var.postgres_runtime_identity_name) != lower(var.candidate_server_name)
      error_message = "Dedicated PostgreSQL runtime identity must not reuse the Entra administrator group name or candidate server name."
    }
  }
}
