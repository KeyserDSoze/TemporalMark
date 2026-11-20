# #132 / ADR 0098: only non-secret identifiers for a FUTURE approval.
# These are computed by AzureRM only at real apply; mocked CI cannot attest
# actual Entra directory ownership, Client ID or PostgreSQL role permission.
# NEVER attach the identity or grant it SQL/RBAC rights in this candidate root.

output "postgres_runtime_identity_resource_id" {
  description = "ARM resource ID for an independently approved future Container Apps UAI attachment; NOT an attached/live identity."
  value       = azurerm_user_assigned_identity.postgres_runtime_candidate.id
}

output "postgres_runtime_identity_client_id" {
  description = "Entra application/client GUID to pin in future #131 ACA token provider; not a PostgreSQL SQL role or authentication secret."
  value       = azurerm_user_assigned_identity.postgres_runtime_candidate.client_id
}

output "postgres_runtime_identity_principal_id" {
  description = "Entra service principal object GUID for separately approved PostgreSQL SQL principal mapping; NOT a granted role."
  value       = azurerm_user_assigned_identity.postgres_runtime_candidate.principal_id
}
