# RED-FIRST #123: mocked Terraform plan, no Azure credentials/state/apply.
# Assert the actual planned Container Apps ingress boundary, not source strings.
mock_provider "azurerm" {}

variables {
  subscription_id            = "00000000-0000-0000-0000-000000000000"
  prefix                     = "tm-ci-ingress"
  location                   = "westeurope"
  storage_account_name       = "tmciingressbound"
  oidc_authority             = "https://identity.example.org/realms/ci"
  postgres_password          = "CI-FAKE-NOT-FOR-DEPLOY"
  registry_connection_string = "CI-FAKE-NOT-FOR-DEPLOY"
  api_image                  = "registry.example.invalid/temporalmark/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  web_image                  = "registry.example.invalid/temporalmark/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}

run "default_both_apps_internal" {
  command = plan

  assert {
    condition     = azurerm_container_app.web.ingress[0].external_enabled == false
    error_message = "Reference Azure PWA must NOT be public by default before CAB/WAF/log/privacy approval."
  }

  assert {
    condition     = azurerm_container_app.api.ingress[0].external_enabled == false
    error_message = "API ingress must remain internal regardless of frontend deployment."
  }

  assert {
    condition     = azurerm_container_app.web.ingress[0].allow_insecure_connections == false && azurerm_container_app.api.ingress[0].allow_insecure_connections == false
    error_message = "Azure web and API ingress must both reject insecure HTTP."
  }

  assert {
    condition     = azurerm_container_app.web.ingress[0].target_port == 80 && azurerm_container_app.api.ingress[0].target_port == 8080
    error_message = "Azure container ingress target ports must remain aligned with Nginx and Kestrel."
  }

  assert {
    condition     = output.frontend_url == null
    error_message = "A private-by-default web app must not report a public frontend_url."
  }
}
