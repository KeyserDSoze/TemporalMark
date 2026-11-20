terraform {
  required_version = ">= 1.8.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.44"
    }
  }
}

# Separate TEST-ONLY candidate root. Never referenced from infra/azure/main.tf.
# No Azure apply credentials, remote state backend or real resources in CI.
provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}
