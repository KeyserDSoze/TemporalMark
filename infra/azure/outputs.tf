output "resource_group" {
  value = azurerm_resource_group.main.name
}

output "frontend_url" {
  description = "Externally reachable web URL only after explicit public ingress opt-in; null in the default internal-only reference."
  value       = var.enable_public_web_ingress ? "https://${azurerm_container_app.web.ingress[0].fqdn}" : null
}

output "postgres_fqdn" {
  value = azurerm_postgresql_flexible_server.registry.fqdn
}

output "evidence_container" {
  value = azurerm_storage_container.evidence.name
}

output "qualification_state" {
  value = "NOT_QUALIFIED"
}
