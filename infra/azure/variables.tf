variable "subscription_id" {
  type        = string
  description = "Azure subscription in which to provision the reference deployment."
}

variable "prefix" {
  type        = string
  default     = "temporalmark"
  description = "Resource name prefix; use distinct prefix per environment."
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "storage_account_name" {
  type        = string
  description = "Globally unique lowercase Azure storage account name, 3-24 characters."
  validation {
    condition     = can(regex("^[a-z0-9]{3,24}$", var.storage_account_name))
    error_message = "Use 3–24 lowercase letters/digits."
  }
}

variable "api_image" {
  type        = string
  description = "Prebuilt publicly pullable ASP.NET Core image (or add private registry identity)."
}

variable "web_image" {
  type        = string
  description = "Prebuilt publicly pullable Nginx React image with correct VITE_OIDC_AUTHORITY."
}

variable "oidc_authority" {
  type        = string
  description = "Public HTTPS OIDC issuer/authority; never a local Keycloak dev issuer."
  validation {
    condition     = startswith(var.oidc_authority, "https://")
    error_message = "A non-development OIDC authority must use HTTPS."
  }
}

variable "postgres_admin" {
  type    = string
  default = "temporalmarkadmin"
}

variable "postgres_password" {
  type        = string
  sensitive   = true
  description = "Azure PostgreSQL bootstrap credential. WARNING: Terraform state contains sensitive data."
}

variable "registry_connection_string" {
  type        = string
  sensitive   = true
  description = "App database connection string, injected as a Container Apps secret; replace with Managed Identity before compliance."
}

variable "evidence_retention_days" {
  type        = number
  default     = 3650
  description = "Pilot WORM policy length; does not automatically delete data when expired, not equivalent to forever."
  validation {
    condition     = var.evidence_retention_days >= 1
    error_message = "Must retain for at least one day."
  }
}
