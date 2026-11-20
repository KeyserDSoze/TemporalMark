# #124 RED-first plan assertions: ACA environment LB is an independent
# network boundary, separate from per-app ingress. AzureRM provider mocked:
# no subscription, no remote state, no apply, and no personal credentials.
mock_provider "azurerm" {}

variables {
  subscription_id            = "00000000-0000-0000-0000-000000000000"
  prefix                     = "tm-ci-env-boundary"
  location                   = "westeurope"
  storage_account_name       = "tmcienvboundary"
  oidc_authority             = "https://id.example.org/realms/ci"
  postgres_password          = "CI-FAKE-DO-NOT-DEPLOY"
  registry_connection_string = "CI-FAKE-DO-NOT-DEPLOY"
  api_image                  = "registry.example.invalid/temporalmark/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  web_image                  = "registry.example.invalid/temporalmark/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}

run "default_internal_environment_and_internal_apps" {
  command = plan

  assert {
    condition     = azurerm_container_app_environment.main.internal_load_balancer_enabled == true
    error_message = "Prequalification ACA environment must use a VNet internal load balancer by DEFAULT."
  }
  assert {
    condition     = azurerm_container_app.web.ingress[0].external_enabled == false && azurerm_container_app.api.ingress[0].external_enabled == false
    error_message = "Both app ingresses must remain internal by default."
  }
  assert {
    condition     = output.frontend_url == null
    error_message = "A private environment must not advertise a public web URL."
  }
}

run "explicit_private_environment_and_apps" {
  command = plan
  variables {
    enable_public_web_ingress = false
  }
  assert {
    condition     = azurerm_container_app_environment.main.internal_load_balancer_enabled == true
    error_message = "Explicit private mode must keep ACA environment internal, not just the app ingress."
  }
  assert {
    condition     = azurerm_container_app.web.ingress[0].external_enabled == false && azurerm_container_app.api.ingress[0].external_enabled == false
    error_message = "Explicit private mode must keep both app ingresses internal."
  }
}

run "explicit_public_web_requires_external_environment_but_private_api" {
  command = plan
  variables {
    enable_public_web_ingress = true
  }
  assert {
    condition     = azurerm_container_app_environment.main.internal_load_balancer_enabled == false
    error_message = "Reviewed public-web opt-in must switch the environment to external mode."
  }
  assert {
    condition     = azurerm_container_app.web.ingress[0].external_enabled == true && azurerm_container_app.api.ingress[0].external_enabled == false
    error_message = "Only the PWA may gain external ingress; API must stay internal."
  }
  assert {
    condition     = azurerm_container_app.web.ingress[0].allow_insecure_connections == false && azurerm_container_app.api.ingress[0].allow_insecure_connections == false
    error_message = "Changing the environment exposure must not allow insecure HTTP."
  }
}
