# Only non-secret, independently approved identifiers. No PostgreSQL
# admin password, login, customer data, OIDC bearer or token variable exists.
variable "subscription_id" {
  type        = string
  description = "Explicit approved Azure subscription for a distinct test server; no implicit subscription."
  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$", var.subscription_id)) && lower(var.subscription_id) != "00000000-0000-0000-0000-000000000000"
    error_message = "Supply an explicit non-zero subscription UUID."
  }
}

variable "resource_group_name" {
  type        = string
  description = "Existing approved resource group; candidate must not create an RG."
  validation {
    condition     = can(regex("^[A-Za-z0-9_().-]{1,90}$", var.resource_group_name)) && !endswith(var.resource_group_name, ".")
    error_message = "Supply a canonical approved Azure resource-group name."
  }
}

variable "location" {
  type        = string
  description = "Independently approved Azure region for a disposable new-server candidate."
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,29}$", var.location))
    error_message = "Supply a canonical lowercase Azure region name."
  }
}

variable "candidate_server_name" {
  type        = string
  description = "New distinct PostgreSQL server name ending -entra-candidate; NEVER the current registry."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,42}-entra-candidate$", var.candidate_server_name))
    error_message = "Only a new lowercase server explicitly ending -entra-candidate is permitted."
  }
}

variable "postgres_subnet_id" {
  type        = string
  description = "Full ARM ID of separately approved delegated PostgreSQL subnet named postgres (verified outside Terraform)."
  validation {
    condition     = can(regex("^/subscriptions/[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}/resourceGroups/[A-Za-z0-9_().-]{1,90}/providers/Microsoft[.]Network/virtualNetworks/[A-Za-z0-9_.-]{2,64}/subnets/postgres$", var.postgres_subnet_id))
    error_message = "Only an existing, explicitly approved VNet postgres delegated subnet ARM ID is permitted."
  }
}

variable "private_dns_zone_id" {
  type        = string
  description = "Full ARM ID of an existing private PostgreSQL DNS zone linked to candidate VNet, independently checked."
  validation {
    condition     = can(regex("^/subscriptions/[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}/resourceGroups/[A-Za-z0-9_().-]{1,90}/providers/Microsoft[.]Network/privateDnsZones/[a-z0-9-]+[.]postgres[.]database[.]azure[.]com$", var.private_dns_zone_id))
    error_message = "Specify an existing PostgreSQL private DNS zone ARM ID ending .postgres.database.azure.com."
  }
}

variable "entra_tenant_id" {
  type        = string
  description = "Explicit independently approved Entra tenant GUID for PostgreSQL token authentication."
  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$", var.entra_tenant_id)) && lower(var.entra_tenant_id) != "00000000-0000-0000-0000-000000000000"
    error_message = "Supply a reviewed non-zero Entra tenant GUID."
  }
}

variable "entra_admin_group_id" {
  type        = string
  description = "Independently authorized Entra group Object ID (NOT an admin password or bearer token)."
  validation {
    condition     = can(regex("^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$", var.entra_admin_group_id)) && lower(var.entra_admin_group_id) != "00000000-0000-0000-0000-000000000000"
    error_message = "Supply a reviewed non-zero Entra administrator group object GUID."
  }
}

variable "entra_admin_group_name" {
  type        = string
  description = "Reviewed canonical Entra administrator group display name; no personal individual admin."
  validation {
    condition     = can(regex("^[A-Za-z][A-Za-z0-9._-]{2,79}$", var.entra_admin_group_name))
    error_message = "Supply a canonical admin group label without whitespace/control characters."
  }
}

# Distinct from the existing API identities (Blob system MI and Key Vault UAI)
# and from the Entra database ADMIN group. No automatic SQL role or grant.
variable "postgres_runtime_identity_name" {
  type        = string
  description = "Independently approved dedicated PostgreSQL runtime user-assigned managed identity, disposable candidate only (never existing API identities)."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,63}-pg-mi-candidate$", var.postgres_runtime_identity_name))
    error_message = "Use a lowercase distinct user-assigned identity name ending -pg-mi-candidate, never a production or existing API identity."
  }
}
