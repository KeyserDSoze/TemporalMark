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
  description = "Reviewed ASP.NET Core OCI image manifest pinned by SHA-256 digest (not a mutable tag); private registry identity is a separate release gate."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$", var.api_image))
    error_message = "api_image must be registry/repository@sha256:<64 lowercase hex digits>; mutable tags and unpinned images are forbidden."
  }
}

variable "web_image" {
  type        = string
  description = "Reviewed Nginx/PWA OCI manifest pinned by SHA-256 digest; verify correct built-in VITE_OIDC_AUTHORITY before publish."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$", var.web_image))
    error_message = "web_image must be registry/repository@sha256:<64 lowercase hex digits>; mutable tags and unpinned images are forbidden."
  }
}

variable "oidc_authority" {
  type        = string
  description = "Reviewed production OIDC issuer: HTTPS DNS FQDN, optional port and nonempty path segments. No userinfo, query, fragment, IP or localhost. Real issuer discovery/JWKS approval remains mandatory."
  validation {
    # Deliberately bounded reference-template syntax, not a URL parser or a
    # trust anchor. OIDC Discovery requires HTTPS and NO query or fragment.
    # DNS-style host requires a final alphabetic label, excluding IP literals.
    # Each path segment starts with an alphanumeric, underscore, tilde or
    # hyphen: no empty, '.' or '..' navigation segments and no trailing '/'.
    condition = can(regex(
      "^https://([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?[.])+[a-z]([a-z0-9-]{0,61}[a-z0-9])?([:][0-9]{1,5})?(/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)*$",
      var.oidc_authority
    ))
    error_message = "oidc_authority must be a reviewed HTTPS DNS FQDN issuer with optional port/path, without IP/localhost, userinfo, query, fragment, empty or dot-path segments."
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
