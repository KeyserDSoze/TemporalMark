# Azure API/web OCI manifest digest pinning — scoped #120

**Pilot release hardening only. Not cryptographic signature verification, SBOM attestation, CAB approval, WORM, GDPR or qualified eIDAS compliance.** See [ADR 0087](../adr/0087-azure-image-oci-sha256-digest-admission.md), parent [#18](https://github.com/KeyserDSoze/TemporalMark/issues/18), open privacy [#115](https://github.com/KeyserDSoze/TemporalMark/issues/115) and [#113](https://github.com/KeyserDSoze/TemporalMark/issues/113).

## Risk and technical boundary

Azure Terraform deploys the two Container Apps from `var.api_image` and `var.web_image`. A mutable image tag such as `:latest` or `:stable` can move to a different manifest, bypassing the precise .NET API and Nginx images previously reviewed in #119/#117. The reference now requires **both** input values in the canonical digest-only form:

```text
registry.example.invalid/temporalmark-api@sha256:<64 lowercase hex characters>
registry.example.invalid/temporalmark-web@sha256:<64 lowercase hex characters>
```

Use the actual registry name/path with an optional numeric port. The `terraform.tfvars.example` contains **intentionally fake digests** and must never be mistaken for a released artifact. Bare names, mutable tags, missing/malformed/uppercase/extended digests and `repo:tag@sha256:...` are rejected by Terraform input validation at **plan** time. This intentionally narrow pattern is *not* a full OCI reference parser, does not support IPv6-registry bracket syntax or private registry authentication, and does not verify that the claimed digest exists or is runnable on the target platform.

An OCI digest is a content reference, **not** proof of who built, signed, scanned, approved or published the image. The Azure Container Apps API may need a provider/CLI/portal-specific capability review before release, including Azure Portal [reported digest-reference issues](https://github.com/microsoft/azure-container-apps/issues/1707). A mocked Terraform plan cannot prove that a real Azure Container App successfully pulls the image or that the service's selected platform is compatible.

## Operator-controlled release steps

1. Build and test the application (same source revision for API .NET 10 and React/Nginx frontend, including prebuilt `VITE_OIDC_AUTHORITY`). Run the complete signed-Keycloak/real-PostgreSQL CI, inspect test logs and confirm Nginx/#117 and API/#119 normal access-log privacy checks against the release candidate. Independently approve SBOM, scan, image signing and supply-chain policy under production parent #18. The existing CI does **not** create/publish signed production OCI images.
2. Push approved artifacts to the **operator-controlled registry** with least-privileged release identity and obtain each immutable manifest or image-index digest from the registry *after publishing*, not by hashing a local tarball or copying an arbitrary manifest SHA from a previous deployment. Validate whether the index or platform-specific manifest is desired and record the selected architecture and exact image reference in the release change request.
3. Replace the **fake** sample `api_image` and `web_image` values with the approved digest-only references. Confirm the API signing/auth settings and the Nginx build-time OIDC authority match the environment. Private-registry authentication and Container Apps ACR pull identity are not delivered by this scoped change.
4. Validate offline syntax and policy with `terraform -chdir=infra/azure init -backend=false`, `terraform -chdir=infra/azure validate`, then `terraform -chdir=infra/azure test -no-color -filter=tests/image_pins.tftest.hcl`. The tests use a **mock `azurerm` provider**, `command=plan`, fake credentials and a list of positive and negative image cases: **no real Azure resources, provider credentials, apply or customer data**. The four-job CI requires these tests in the Terraform job.
5. In an **approved Azure subscription** and controlled environment, inspect an actual `terraform plan`/deployment change with real authorized state and credential management, check that the registry resolves to the expected digest/architecture and that the running revision actually uses it. Configure image pull identity, signed OCI provenance verification, vulnerability gates, safe canary rollout and rollback according to parent #18 before any claim of production readiness.

## What stays open

No registry signature/cosign/notary verification, transparency witness, trusted builder attestation, SBOM binding, artifact-retention lock, ACR Managed Identity pull, image scanning/approval workflow, Azure deployment proof, multi-region DR or CAB-compliant production release is provided. Container Apps managed ingress telemetry and Azure Log Analytics retention remain unverified. Backups/GDPR-DPIA and edge controls remain #115/#113, and legal QTSP/eIDAS/WORM claims remain blocked by #13/#15/#17. WebAuthn reviewer/registrar V015/V016 stop-lines remain unchanged; pilot evidence still `Unverified`.

Sources: [OCI Distribution Specification](https://specs.opencontainers.org/distribution-spec/), [OCI image digest reference](https://oras.land/docs/concepts/reference/), [HashiCorp Terraform input validation](https://developer.hashicorp.com/terraform/language/block/variable), [Terraform mock-provider tests](https://developer.hashicorp.com/terraform/language/tests/mocking).
