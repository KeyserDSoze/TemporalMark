terraform {
  required_version = ">= 1.8.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.14"
    }
  }
}

# Storage Shared Key is disabled. Blob container data-plane management
# requires a private-network Terraform runner with Azure AD/RBAC access.
provider "azurerm" {
  features {}
  subscription_id     = var.subscription_id
  storage_use_azuread = true
}

data "azurerm_client_config" "current" {}
