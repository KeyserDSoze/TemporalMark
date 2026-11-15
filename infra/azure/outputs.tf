output "resource_group" {
  value = azurerm_resource_group.main.name
}

output "frontend_url" {
  value = "https://${azurerm_container_app.web.ingress[0].fqdn}"
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
