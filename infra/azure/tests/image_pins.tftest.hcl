# Plan-only, mocked provider; no Azure API calls, customer images, remote state
# or real credentials. RED-first #120: mutable image refs must be rejected.
mock_provider "azurerm" {}

variables {
  subscription_id            = "00000000-0000-0000-0000-000000000000"
  prefix                     = "tm-ci-image-pins"
  location                   = "westeurope"
  storage_account_name       = "tmsyntheticimagepins"
  oidc_authority             = "https://id.example.invalid/realms/ci"
  postgres_password          = "CI-FAKE-DO-NOT-DEPLOY"
  registry_connection_string = "CI-FAKE-DO-NOT-DEPLOY"
  api_image                  = "registry.example.invalid:5000/temporalmark/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  web_image                  = "registry.example.invalid:5000/temporalmark/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}

run "valid_api_and_web_pinned_digests" {
  command = plan
}

run "reject_mutable_api_tag" {
  command = plan
  variables {
    api_image = "registry.example.invalid/temporalmark/api:latest"
  }
  expect_failures = [var.api_image]
}

run "reject_unversioned_api_image" {
  command = plan
  variables {
    api_image = "registry.example.invalid/temporalmark/api"
  }
  expect_failures = [var.api_image]
}

run "reject_short_api_digest" {
  command = plan
  variables {
    api_image = "registry.example.invalid/temporalmark/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  }
  expect_failures = [var.api_image]
}

run "reject_extra_api_digest_suffix" {
  command = plan
  variables {
    api_image = "registry.example.invalid/temporalmark/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0"
  }
  expect_failures = [var.api_image]
}

run "reject_uppercase_api_digest" {
  command = plan
  variables {
    api_image = "registry.example.invalid/temporalmark/api@sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  }
  expect_failures = [var.api_image]
}

run "reject_mutable_web_tag" {
  command = plan
  variables {
    web_image = "registry.example.invalid/temporalmark/web:latest"
  }
  expect_failures = [var.web_image]
}

run "reject_missing_web_digest" {
  command = plan
  variables {
    web_image = "registry.example.invalid/temporalmark/web"
  }
  expect_failures = [var.web_image]
}

run "reject_nonhex_web_digest" {
  command = plan
  variables {
    web_image = "registry.example.invalid/temporalmark/web@sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
  }
  expect_failures = [var.web_image]
}

run "reject_both_tag_and_digest" {
  command = plan
  variables {
    web_image = "registry.example.invalid/temporalmark/web:latest@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
  }
  expect_failures = [var.web_image]
}

run "reject_whitespace_in_web_reference" {
  command = plan
  variables {
    web_image = "registry.example.invalid/temporalmark/web@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "
  }
  expect_failures = [var.web_image]
}
