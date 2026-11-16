# Nine-project NuGet locked-mode build and restore — #79

**Scope:** versioned .NET 10 NuGet resolution for five production and four test projects, with no claim of signed release, SCA, attested source or legal qualification. Decision [ADR 0049](../adr/0049-nuget-locked-restoration-ci-docker.md); parent [#20](https://github.com/KeyserDSoze/TemporalMark/issues/20).

## Provenance and TDD evidence

Real [CI 43883455966](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43883455966), SHA `5fd98af24255ae8d1d94933049d897ff760e009c`: source policy regression tests passed and the repository gate failed as designed on all nine absent `packages.lock.json` files and mutable SDK restore commands. Its independent temporary `nuget-lock-seed` job succeeded, running `dotnet restore "$project" --use-lock-file --verbosity quiet` with GitHub Actions .NET 10 and NuGet registry connectivity. The runner emitted ONLY nine public versioned `packages.lock.json` contents in paired `TEMPORALMARK_NUGET_LOCK_BEGIN/END` base64 blocks, without secret files, credentials or `obj/project.assets.json`.

The nine byte-exact generated lockfiles (62,364 bytes total; schema 1, `net10.0`) were validated as JSON and checked for SHA-512 package hashes and committed to `main` in [6717fa3](https://github.com/KeyserDSoze/TemporalMark/commit/6717fa310e0604283590316b1946e1da6318deb7). The temporary seed and all base64 logging were removed before GREEN in [e10f17d](https://github.com/KeyserDSoze/TemporalMark/commit/e10f17d72976daf52d7bc25ed14f42de29cdcdbf).

## Enforced gates

- Offline source policy requires exactly nine matching lockfiles and fixed canonical SHA-512 package versions: `python3 -m unittest discover -s tests/integration -p 'test_check_nuget_lockfiles.py' -v` and `python3 tests/integration/check_nuget_lockfiles.py`.
- Backend CI runs `dotnet restore "$project" --locked-mode` on **all nine** before any application build/test; it uses `--no-restore` for subsequent backend tests, publishes and the V015 interlock probe. NuGet CycloneDX still inventories those *actual restored* assets.
- API Docker builder runs `dotnet publish -p:RestoreLockedMode=true`; PostgreSQL and Keycloak integration tests set the same property. No lock is generated or silently updated in a required GREEN job.
- Exact-head main must finish backend, frontend, docker-smoke and terraform successfully, including real PostgreSQL witness restore, Keycloak TOTP/PKCE and the production mobile PWA smoke, before closing #79 or #80. No temporary seed is permitted in the final run.

Local reproduction with .NET 10 SDK and Python 3:

```sh
python3 -m unittest discover -s tests/integration -p 'test_check_nuget_lockfiles.py' -v
python3 tests/integration/check_nuget_lockfiles.py
find src/backend tests/backend -name '*.csproj' -print0 | sort -z | xargs -0 -n1 dotnet restore --locked-mode
```

## Limitations

NuGet's content hashes represent recorded registry packages but do not prove author identity, malware absence, SLSA provenance, runtime byte reproducibility, available future feeds, SDK-image compatibility or installed OS/container libraries. Reviewed dependency updates require regenerating locks via `--use-lock-file` and a full GREEN CI. Security #64/#61/#57/#17, reviewer/registrar V015/V016 suspension and the distinction between TemporalMark and a qualified QTSP are not affected. Parent #20 remains OPEN for complete artifact attestation, SAST/SCA, physical mobile installation and cross-tenant end-to-end coverage.
