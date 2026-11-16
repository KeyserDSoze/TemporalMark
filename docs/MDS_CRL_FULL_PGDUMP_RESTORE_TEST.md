# Full PostgreSQL 17 logical pg_dump/pg_restore vs a synthetic latest signed seal (#66)

**Test-only, non-authorizing.** This is a full *logical database archive* restore **on the same disposable PostgreSQL 17 server**, NOT production disaster recovery, WAL/PITR, storage immutability, a separately custodied high-water authority, official FIDO MDS trust, WORM evidence or a qualified timestamp. It implements [ADR 0035](../adr/0035-test-only-full-logical-pg-dump-restore-vs-signed-seal.md). Parent [#64](https://github.com/KeyserDSoze/TemporalMark/issues/64), [#61](https://github.com/KeyserDSoze/TemporalMark/issues/61) and [#57](https://github.com/KeyserDSoze/TemporalMark/issues/57) remain OPEN.

## What actually runs in Docker CI

The mandatory `docker-smoke` workflow step `Real PostgreSQL full logical pg_dump and pg_restore sealed-witness rollback regression` runs `bash tests/integration/mds-full-pgdump-restore.sh` **after** the existing tenant/migration/concurrency tests and before OIDC/Keycloak MFA. Its own failure stops the job.

1. Create a fresh synthetic `MDS_BLOB` V017 source-policy scope and issuer SHA256, stage **serial 3** using the existing *owner-only* `record_unapproved_mds_checkpoint_candidate` function. These are **untrusted hashes**, not real manufacturer metadata.
2. Run **`pg_dump --format=custom` over the WHOLE `temporalmark` test database**, saving a private, non-uploaded archive in the runner's `mktemp -d`; do not alter any applied V001–V017 migration.
3. Stage **serial 4** on the primary under the same scope and original source fingerprint. Create **a separate, unique, disposable PostgreSQL database** with `createdb --template=template0`; restore the old archive using `pg_restore --single-transaction --exit-on-error --no-owner`. **Preserve ACLs**; do **not** use `--no-acl`, which could resurrect `PUBLIC EXECUTE` privileges or remove intended table-role restrictions after restore.
4. Verify the restored database retains all **17 migration history records**, the old scoped candidate's serial 3 and the revoked function privileges for ordinary application roles; verify the live original's corresponding candidate is serial 4. Original primary is never overwritten. A guarded trap removes the disposable database and archive even if a command fails.
5. Run a dedicated .NET 10 xUnit `MdsFullPgDumpRestorePostgresTests` method against **both databases**, generating two ephemeral RSA-PSS SHA256 keys (witness and independent test seal key) and holding the newest test seal digest/SPKI pin **only in test-process memory**. Reuse the ADR 0034 `ReviewerMdsOfflineSealedHighWaterCandidateVerifier` and its ADR 0033 PostgreSQL **REPEATABLE READ READ ONLY** verification; do not invent a second signature or snapshot verifier.

The xUnit test requires positive `UNAPPROVED` for the current serial 4 + signed newest witness/seal. It rejects newest signed witness against restored serial 3; rejects old correctly signed serial-3 witness+seal **under the retained serial-4 seal digest**; rejects same-serial evidence digest tampering; and explicitly demonstrates that if the caller maliciously substitutes the **old test latest-seal hash** along with the old database/witness/seal, the observation can again be `UNAPPROVED` rather than a denial. There is no result of `TRUSTED`, no key activation, and no SQL grant to reviewer or registrar.

## Security and operational limitations

- `pg_dump/pg_restore` verifies **logical backup/restore of the full test database into a second database on the SAME server**. It is not a physical cluster backup, WAL/PITR, a whole-environment restore, an availability test, recovery across Azure regions, an independently isolated backup vault, multi-tenancy DR certification or retention/WORM validation. The archive is CI-only; never run this fixture against real production data or credentials.
- The test 'external' latest SHA is simply a value in the same test process, **not an independently immutable held monotonic state**. An adversary able to replace it with the earlier SHA can replay the fully restored database and the earlier valid signatures. Production #64 must specify and implement separate CAB-approved signing root/key bootstrap, HSM or equivalent independent custody, externally monotonic append-only storage, authentication and separation of control of witness/DB operators, rotation, expiry, monitoring, outage and backup recovery policy, real full-cluster PITR and cross-region split-brain tests.
- V017 stores **caller-supplied issuer key and source hashes**; a successfully reconciled snapshot does not establish FIDO Alliance GlobalSign R46 trust, correct R3/R46 cross-chain, authentic signed MDS JWS or issuer-scoped all-hop CRL/OCSP/CRLNumber, trustworthy time or attestation model status. Those are #57/#55 release blockers. Reviewer-held hardware device registration, two-person authorization, role provenance and the one-time atomic approval remain #53/#44/#50/#46/#38 blockers.
- Both OSS on-prem and Azure may use their own controlled PostgreSQL logical backup mechanisms, but *equivalent secure* production DR is **not implemented or tested** here. **V015/V016 registrar issuance freeze and suspended registrar CLI remain unchanged**, and no API, database migration, privilege, FIDO credential, eIDAS/WORM or QTSP legal claim is introduced.

## Evidence

- [ADR 0035](../adr/0035-test-only-full-logical-pg-dump-restore-vs-signed-seal.md)
- [Existing signed seal verifier](MDS_CRL_SEALED_HIGH_WATER_COPY_RESTORE.md)
- [PostgreSQL 17 pg_dump](https://www.postgresql.org/docs/17/app-pgdump.html)
- [PostgreSQL 17 pg_restore](https://www.postgresql.org/docs/17/app-pgrestore.html)
- [#66 TDD issue and CI evidence](https://github.com/KeyserDSoze/TemporalMark/issues/66)
