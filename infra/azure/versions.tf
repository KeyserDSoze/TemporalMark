terraform {
  required_version = ">= 1.8.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.44"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id     = var.subscription_id
  # Storage Shared Key is disabled. Blob container data-plane management
  # requires a private-network Terraform runner with Azure AD/RBAC access.
  storage_use_azuread = true
}

data "azurerm_client_config" "current" {}
