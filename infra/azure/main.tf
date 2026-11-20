locals {
  tags = {
    application = "TemporalMark"
    environment = "prequalification"
    compliance  = "NOT_QUALIFIED"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "main" {
  name                = "${var.prefix}-vnet"
  address_space       = ["10.40.0.0/16"]
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_subnet" "apps" {
  name                 = "apps"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.40.1.0/24"]
  delegation {
    name = "aca"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_subnet" "postgres" {
  name                 = "postgres"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.40.2.0/24"]
  delegation {
    name = "postgres-flexible"
    service_delegation {
      name    = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

# Blob Private Link must use a dedicated, NON-delegated subnet.
# Delegated ACA and PostgreSQL subnets are not valid PE destinations.
resource "azurerm_subnet" "evidence_private_endpoint" {
  name                              = "blob-private-endpoints"
  resource_group_name               = azurerm_resource_group.main.name
  virtual_network_name              = azurerm_virtual_network.main.name
  address_prefixes                  = ["10.40.3.0/24"]
  private_endpoint_network_policies = "Disabled"
}

resource "azurerm_private_dns_zone" "postgres" {
  name                = "${var.prefix}.postgres.database.azure.com"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "postgres-vnet"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = azurerm_virtual_network.main.id
}

resource "azurerm_postgresql_flexible_server" "registry" {
  name                          = "${var.prefix}-pg"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = var.location
  version                       = "17"
  delegated_subnet_id           = azurerm_subnet.postgres.id
  private_dns_zone_id           = azurerm_private_dns_zone.postgres.id
  public_network_access_enabled = false
  administrator_login           = var.postgres_admin
  administrator_password        = var.postgres_password
  storage_mb                    = 32768
  sku_name                      = "B_Standard_B1ms"
  backup_retention_days         = 14
  tags                          = local.tags

  depends_on = [azurerm_private_dns_zone_virtual_network_link.postgres]
}

resource "azurerm_postgresql_flexible_server_database" "registry" {
  name      = "temporalmark"
  server_id = azurerm_postgresql_flexible_server.registry.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_storage_account" "evidence" {
  name                            = var.storage_account_name
  resource_group_name             = azurerm_resource_group.main.name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "ZRS"
  account_kind                    = "StorageV2"
  min_tls_version                 = "TLS1_2"
  https_traffic_only_enabled      = true
  public_network_access_enabled   = false
  allow_nested_items_to_be_public = false
  shared_access_key_enabled       = false
  tags                            = local.tags

  blob_properties {
    versioning_enabled  = true
    change_feed_enabled = true
  }

  lifecycle {
    prevent_destroy = true
  }
}

# Private Blob DNS and endpoint are a separate network boundary from
# ACA ingress. A real Terraform apply must run on a private-network agent.
resource "azurerm_private_dns_zone" "evidence_blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "evidence_blob" {
  name                  = "blob-evidence-vnet"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.evidence_blob.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = false
}

resource "azurerm_private_endpoint" "evidence_blob" {
  name                = "${var.prefix}-evidence-blob-pe"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.evidence_private_endpoint.id
  tags                = local.tags

  private_service_connection {
    name                           = "evidence-blob"
    private_connection_resource_id = azurerm_storage_account.evidence.id
    is_manual_connection           = false
    subresource_names              = ["blob"]
  }

  private_dns_zone_group {
    name                 = "evidence-blob-private-dns"
    private_dns_zone_ids = [azurerm_private_dns_zone.evidence_blob.id]
  }
}

resource "azurerm_storage_container" "evidence" {
  name                  = "timestamp-evidence"
  storage_account_id    = azurerm_storage_account.evidence.id
  container_access_type = "private"

  # AzureRM container creation uses the Blob data plane. Do not race ahead of
  # the private endpoint/DNS setup. Apply runner must resolve/reach private IP.
  depends_on = [
    azurerm_private_endpoint.evidence_blob,
    azurerm_private_dns_zone_virtual_network_link.evidence_blob
  ]

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_storage_container_immutability_policy" "evidence" {
  storage_container_resource_manager_id = azurerm_storage_container.evidence.resource_manager_id
  immutability_period_in_days           = var.evidence_retention_days
  protected_append_writes_enabled       = false
  protected_append_writes_all_enabled   = false
  locked                                = false # CAB/legal approval mandatory before irreversible lock.
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.prefix}-logs"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

resource "azurerm_container_app_environment" "main" {
  name                           = "${var.prefix}-apps"
  location                       = var.location
  resource_group_name            = azurerm_resource_group.main.name
  infrastructure_subnet_id       = azurerm_subnet.apps.id
  internal_load_balancer_enabled = !var.enable_public_web_ingress
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.main.id
  tags                           = local.tags
}

resource "azurerm_container_app" "api" {
  name                         = "${var.prefix}-api"
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = azurerm_container_app_environment.main.id
  revision_mode                = "Single"
  tags                         = local.tags

  identity { type = "SystemAssigned" }

  secret {
    name  = "registry-connection"
    value = var.registry_connection_string
  }

  template {
    min_replicas = 1
    max_replicas = 2

    container {
      name   = "api"
      image  = var.api_image
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "ASPNETCORE_ENVIRONMENT"
        value = "Production"
      }
      env {
        name  = "Authentication__Authority"
        value = var.oidc_authority
      }
      env {
        name  = "Authentication__Audience"
        value = "temporalmark-api"
      }
      env {
        name        = "ConnectionStrings__Registry"
        secret_name = "registry-connection"
      }
    }
  }

  ingress {
    external_enabled           = false
    allow_insecure_connections = false
    target_port                = 8080
    transport                  = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
}

resource "azurerm_container_app" "web" {
  name                         = "${var.prefix}-web"
  resource_group_name          = azurerm_resource_group.main.name
  container_app_environment_id = azurerm_container_app_environment.main.id
  revision_mode                = "Single"
  tags                         = local.tags

  template {
    min_replicas = 1
    max_replicas = 2

    container {
      name   = "web"
      image  = var.web_image
      cpu    = 0.5
      memory = "1Gi"

      env {
        name  = "API_UPSTREAM"
        value = "http://${azurerm_container_app.api.name}"
      }
      env {
        name  = "NGINX_ENVSUBST_FILTER"
        value = "^API_UPSTREAM$"
      }
    }
  }

  ingress {
    external_enabled           = var.enable_public_web_ingress
    allow_insecure_connections = false
    target_port                = 80
    transport                  = "auto"
    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }
}

resource "azurerm_role_assignment" "api_evidence_writer" {
  scope                = azurerm_storage_account.evidence.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_container_app.api.identity[0].principal_id
}
