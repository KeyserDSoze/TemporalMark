# RED-first #122: real Terraform plan-only mocked Azurerm OIDC issuer guard.
# No remote Azure backend, credentials, external HTTP, real tokens or applies.
mock_provider "azurerm" {}

variables {
  subscription_id                  = "00000000-0000-0000-0000-000000000000"
  prefix                           = "tm-ci-issuer-guard"
  location                         = "westeurope"
  storage_account_name             = "tmciissuerguard"
  oidc_authority                   = "https://id.example.org/realms/ci"
  postgres_password                = "CI-FAKE-NOT-FOR-DEPLOY"
  registry_connection_secret_uri   = "https://tmciregistryvault.vault.azure.net/secrets/registry-connection/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  registry_connection_key_vault_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/tm-ci-kv-rg/providers/Microsoft.KeyVault/vaults/tmciregistryvault"
  api_image                        = "registry.example.invalid/temporalmark/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  web_image                        = "registry.example.invalid/temporalmark/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}

run "accept_keycloak_realm_https" {
  command = plan
}

run "accept_entra_tenant_version_path" {
  command = plan
  variables {
    oidc_authority = "https://login.microsoftonline.com/01234567-89ab-4cde-8123-456789abcdef/v2.0"
  }
}

run "accept_fqdn_with_explicit_tls_port" {
  command = plan
  variables {
    oidc_authority = "https://identity.example.org:8443/realms/approved-team"
  }
}

run "reject_plain_http_issuer" {
  command = plan
  variables {
    oidc_authority = "http://id.example.org/realms/ci"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_missing_https_hostname" {
  command = plan
  variables {
    oidc_authority = "https://"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_loopback_localhost" {
  command = plan
  variables {
    oidc_authority = "https://localhost:8081/realms/ci"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_raw_loopback_ipv4" {
  command = plan
  variables {
    oidc_authority = "https://127.0.0.1/realms/ci"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_ip_address_nonloopback" {
  command = plan
  variables {
    oidc_authority = "https://10.40.0.1/realm"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_userinfo_credentials" {
  command = plan
  variables {
    oidc_authority = "https://admin:pass@id.example.org/realms/ci"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_misleading_host_userinfo" {
  command = plan
  variables {
    oidc_authority = "https://id.example.org@evil.example.net/realms/ci"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_issuer_query" {
  command = plan
  variables {
    oidc_authority = "https://id.example.org/realms/ci?tenant=B"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_issuer_fragment" {
  command = plan
  variables {
    oidc_authority = "https://id.example.org/realms/ci#sub"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_trailing_issuer_slash" {
  command = plan
  variables {
    oidc_authority = "https://id.example.org/realms/ci/"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_issuer_whitespace" {
  command = plan
  variables {
    oidc_authority = "https://id.example.org/realms/ci "
  }
  expect_failures = [var.oidc_authority]
}

run "reject_dot_dot_path_segment" {
  command = plan
  variables {
    oidc_authority = "https://id.example.org/realms/../admin"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_double_slash_path_segment" {
  command = plan
  variables {
    oidc_authority = "https://id.example.org/realms//ci"
  }
  expect_failures = [var.oidc_authority]
}

run "reject_single_label_issuer_host" {
  command = plan
  variables {
    oidc_authority = "https://identity/realms/ci"
  }
  expect_failures = [var.oidc_authority]
}
