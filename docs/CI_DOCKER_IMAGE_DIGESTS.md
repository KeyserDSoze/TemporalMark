# CI/dev Docker manifest digest pins — #76

**SCOPE: disposable development/CI stack ONLY.** ADR 0045 and scoped [issue #76](https://github.com/KeyserDSoze/TemporalMark/issues/76), child of open #20. These image selections are not certified production components, immutable evidence or qualified timestamping.

## Public registry provenance (2026-11-16)

`docker buildx imagetools inspect` executed inside an independent GitHub Actions Ubuntu frontend runner, observing public registry manifest/index digests. First RED attempt [43868733873](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43868733873) failed before returning any manifest. The revised diagnostic [run 43869063858](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43869063858) successfully returned **all six** of these tag-to-digest pairs without any secrets or tokens. No guessed or fallback SHA values are used.

| Original human-readable tag | Observed OCI registry SHA256 |
|---|---|
| `postgres:17.6-alpine` | `sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94` |
| `quay.io/keycloak/keycloak:26.4.0` | `sha256:5f3fb534cde6bf006d79f5912473e5d2c828c707cdfc52e16972803aca9d43dd` |
| `node:22-alpine` | `sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a` |
| `nginx:1.27-alpine` | `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10` |
| `mcr.microsoft.com/dotnet/sdk:10.0` | `sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb` |
| `mcr.microsoft.com/dotnet/aspnet:10.0` | `sha256:bfd912c83295ce66d4b706ebb8541b9f14259b0e76fbb88b2751f58ce2399d2e` |

Compose uses **one identical pinned PostgreSQL manifest** for its three services: the main disposable database, the CI-only `witness-postgres`, and the migration runner. `quay.io/keycloak/keycloak:26.4.0` remains the CI identity server. The backend Dockerfile pins .NET 10 SDK and ASP.NET runtime independently; the frontend Dockerfile pins Node 22 Alpine and nginx 1.27 Alpine. All eight references use `name:tag@sha256:<64 lowercase hex>`. Tags are descriptive; the digest controls image bytes via registry manifest lookup.

## TDD and CI checks

ADR 0045 was committed first at `17ae8d3`. RED Python-stdlib policy and regression tests were introduced on main in `3074d7d`. [Actual RED CI 43868733873](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43868733873): **5/5 policy test regressions passed**, then the repository policy failed with source path/line errors identifying **all eight floating occurrences**. A diagnostic change to the temporary manifest seed followed at `3d0c098` and retrieved six registry digests on [CI 43869063858](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43869063858). GREEN code `16a962a` pins all original image refs and completely removes the temporary runtime registry discovery step. `tests/integration/check_container_image_pins.py` is enforced early in the backend job and covers Dockerfile build stage aliases, malformed/dynamic references, Compose source and full sha256 length. No conditional fallback on registry errors.

**Do not mark delivery complete or close #76 without SUCCESS of all four CI jobs on the exact final `main` SHA**, including real Docker builds, full logical PostgreSQL backup/restore with separate witness, PWA service-worker test, Keycloak browser MFA/PKCE and Terraform validation.

## Update procedure and residual concerns

To update a pinned image, review the publisher's release/security changes and registry provenance, retrieve the *new tag and exact observed digest* in a controlled environment (e.g. `docker buildx imagetools inspect name:tag`), check architecture variants, update every relevant source, run policy and complete CI, attach the observed manifest to a GitHub issue, and obtain operational approval before release. Do not revert to floating tags if the digest is unavailable or stale. Vulnerable pinned images require timely review and rotation: a digest freezes known vulnerabilities as well as reducing drift.

An OCI manifest index may contain different OS/architecture images, attestations and software content; digest pinning alone does not verify a publisher signature or software quality. Runner OS, GitHub buildx version, platform selection, Playwright browser binaries, .NET NuGet packages, native install-time network and Terraform providers remain variable. Security scanners/SBOM, provenance/attestation verification and approved release policies are still required. The local Compose stack is **not** a production on-prem OSS/Azure qualified service; no CAB, eIDAS/QTSP, UTC(k), approved FIDO MDS R46 root, HSM or independently immutable high-water custody is supplied. Parent #20 and #64/#61/#57/#17 remain open; V015/V016 authorization remains frozen.

Sources: [Docker imagetools inspect](https://docs.docker.com/reference/cli/docker/buildx/imagetools/inspect), [Docker base-image version pinning](https://docs.docker.com/build/building/best-practices/#pin-base-image-versions).
