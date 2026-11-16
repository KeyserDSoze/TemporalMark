# MDS / CRL — owner-only UNAPPROVED PostgreSQL checkpoint staging (#62)

**Status: SQL-only diagnostic candidate registry; NOT FIDO trust, not persistent disaster-recovery anti-rollback and not an attestation authorization.** See [ADR 0032](../adr/0032-owner-only-unapproved-mds-crl-checkpoint-staging.md), parent [#61](https://github.com/KeyserDSoze/TemporalMark/issues/61) and security root+CRL parent [#57](https://github.com/KeyserDSoze/TemporalMark/issues/57). The V015/V016 registrar security freeze, suspended registrar CLI, #55/#53/#44/#50/#46/#38 remain intact.

## What V017 stores

The new **forward-only checksummed V017** creates `public.mds_unapproved_candidate_checkpoints` (one row per `candidate_kind, issuer_key_sha256`) and `public.mds_unapproved_candidate_events` (one append-only-by-trigger event per *first or strictly increasing* revision). It uses only these fields:

- `candidate_kind`: `MDS_BLOB` (a claimed signed MDS `no`), or `ISSUER_CRL` (a claimed issuer-scoped CRL number).
- `issuer_key_sha256`: an **untrusted caller-supplied** uppercase 64-digit hex digest identifying a claimed signer/CRL issuer; not a root certificate or independently authenticated provenance.
- `source_policy_sha256`: an **untrusted caller-supplied** 64-digit fingerprint, pinned for a kind+issuer in this local DB only. It is *not* proof of a CAB-approved root, trust store or signed import.
- `signed_evidence_sha256`: digest of **caller-supplied** purported signed evidence; SQL does **not** parse or verify the JWS, CRL signatures, revocation or any timestamp of that evidence.
- Positive `candidate_serial`, 8–128-character change reference, PostgreSQL `observed_utc` and `expires_utc`, with a bounded 60–86400-second TTL. `review_status` is always **`UNAPPROVED`**.

**There is no data-plane consumer or runtime importer.** No private keys, JWT/CRL bytes, x5c chains, certificate identifiers or PII are stored. A passing SQL row is **not verified FIDO metadata**, and any malicious migration owner can stage arbitrary hashes.

## Transaction and security model

Only the **physical PostgreSQL table-owner login** may call `public.record_unapproved_mds_checkpoint_candidate(text,text,bigint,text,text,integer,text)`. The function is SECURITY INVOKER (not SECURITY DEFINER), explicitly checks `session_user=current_user=table owner`, and has **no grants** to PUBLIC, runtime, approver, provisioner or credential registrar groups. All newly created checkpoint/history tables and the history trigger function are inaccessible to those roles. An accidental standalone direct function EXECUTE grant to another login still fails its database owner-session check; PostgreSQL owner/superuser can always bypass normal controls.

The first version for a key creates a checkpoint and one event inside a transaction. All later calls serialize via unique-index `ON CONFLICT DO NOTHING` + `SELECT ... FOR UPDATE` on the existing row; equal version + equal digest and pinned source is strictly **idempotent** and **does not refresh expiry or create another event**. A higher positive version with the original source fingerprint advances the checkpoint and appends one event. Lower versions, equal version with different bytes/digest, changed source policy, expiration or clock moving behind the stored observation cause a SQL **fail-closed rejection**. A checkpoint that expired is quarantined even for a higher number; recovery needs an independently approved process. SQL CHECK constraints enforce field bounds; a trigger blocks ordinary UPDATE/DELETE of the event history, but does **not** make the table tamper-proof against owners/superusers or backups.

**Important:** the monotonic guarantee is ONLY within the **current writable PostgreSQL primary and its current history**. Replication conflicts, restoring a prior database snapshot, owner-level table manipulation, checkpoint corruption/erasure, cross-region split-brain and rollbacks of independent trusted clocks **cannot be detected reliably** without a separate signed/immutable witness. External notarization/HSM, signed provenance, verified root custody and durable recovery procedures are explicitly outstanding under #61.

## Live integration evidence and deployment

The `MdsUnapprovedCheckpointPostgresTests` xUnit suite runs in Docker CI against real PostgreSQL 17: first/equal/higher version, same-revision equivocation, independent CRL/MDS issuer IDs, missing/malformed hash/version/TTL, expired/future-observed snapshot, no history mutation, actual app-role privilege denial, and competing concurrent same-key writers (including conflicting equal serials). Test setup **never seeds a new production signer or privileged SQL login**. CI now expects **17** checksum-verified migrations, and V001–V016 remain unchanged.

For on-prem use the existing PostgreSQL migration-owner one-shot migrator with an authorized, reviewed **V017** upgrade; Azure must use the equivalent controlled migration job, not automatic Terraform application. Avoid storing production CRL/JWT or private/root material in this candidate table. The presence of the table itself must never allow the registrar CLI, reviewer enrollment, pending-approval SQL DML, timestamp issuance or download.

## Remaining requirements under #61/#57/#55

- **Independent FIDO R46 root governance and actual JWS/x5c signing chain**. The FIDO [MDS changelog](https://fidoalliance.org/mds-changelog/) documents August 2026 GlobalSign R3→R46 migration and R3 cross-cert ending 2029-03-18.
- **Cryptographically verified issuer-bound CRLs and trusted distribution** (AKI/CDP, signed CRLNumber and optional OCSP, no insecure URL/SSRF, authenticated offline import and fail-closed outage). #59/#60 only verify synthetic certificate chains and local real signatures with untrusted test roots.
- **Independent durable anti-rollback witness and restore reconciliation**: a signed immutable checkpoint beyond the mutable DB, backup+restore and split-brain tests, non-circular monotonic authority, clock and eventual consistency policy, and review of real signer-root rollover.
- **Separate organizational governance**: an approved security CAB, DPIA/privacy review, device AAGUID attestation status, independently registered reviewer-held hardware keys, signed human intent, atomic one-time SQL approval and role/credential revocation; all associated blocker issues stay OPEN.

## References

- [ADR 0032](../adr/0032-owner-only-unapproved-mds-crl-checkpoint-staging.md)
- [PostgreSQL 17 ON CONFLICT](https://www.postgresql.org/docs/17/sql-insert.html)
- [PostgreSQL 17 row-level locks](https://www.postgresql.org/docs/17/explicit-locking.html)
- [FIDO MDS changelog](https://fidoalliance.org/mds-changelog/)

## Detached signed witness preflight remains non-authorizing (#63)

ADR 0033 adds the [offline witness reconciliation runbook](MDS_CRL_SIGNED_WITNESS_RECONCILIATION.md) and a .NET 10 RSA-PSS SHA256 verification test against a PostgreSQL read-only, repeatable-read snapshot of one full source-policy partition. A signed manifest with **test-only caller-supplied key** can expose a restored-lower-version or changed digest when compared against the local V017 rows. It does **not** prove the test key is independently approved, the witness is the newest version, that production FIDO root R46/MDS CRLs have authentic provenance, or that an old database and old witness cannot be replayed together. The standalone witness result remains `UNAPPROVED`; no V018, CLI, SQL grant, enrollment or trusted metadata source is added. #61 and #57 remain open for true independent high-water-mark custody and audited R46 certificate revocation.
