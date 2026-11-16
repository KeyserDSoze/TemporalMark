# Test-only latest sealed witness and scoped PostgreSQL COPY rollback (#65)

**Status: experimental/non-authorizing.** This is NOT an independently protected latest high-water mark, real FIDO Metadata Service trust, backup/disaster recovery certification, WORM preservation or qualified timestamping. The [ADR 0034](../adr/0034-test-only-sealed-high-water-witness-and-scoped-copy-restore.md) and scoped child [#65](https://github.com/KeyserDSoze/TemporalMark/issues/65) deliberately keep [#64](https://github.com/KeyserDSoze/TemporalMark/issues/64), [#61](https://github.com/KeyserDSoze/TemporalMark/issues/61), and [#57](https://github.com/KeyserDSoze/TemporalMark/issues/57) open.

## What was implemented

`ReviewerMdsOfflineSealedHighWaterCandidateVerifier` is an isolated .NET 10 preflight. It requires TWO independently signed objects and TWO explicit source-of-truth **test** pins provided by the caller (not stored in SQL or app configuration):

1. The existing ADR 0033 strict signed witness, with its own separate RSA-PSS/SHA256 test signer, source-policy partition and claim that each row has a certain issuer hash, version and evidence digest.
2. A new domain-separated **seal**, signed with a second ephemeral RSA-PSS/SHA256 **test authority key**, binds the exact witness SHA256, source-policy hash, UTC issue/expiry epoch seconds.
3. A SHA256 pin of the seal authority's SubjectPublicKeyInfo, **plus** a SHA256 pin of the exact latest seal, each retained by the caller **outside the PostgreSQL test database**. If either is missing/modified, the operation fails closed. The latest seal pin is essential: a valid but old seal from the same signing key otherwise remains correctly signed.

The seal must be canonical uppercase ASCII, terminal-LF, no extra fields/CR/tabs/whitespace, fixed domain, two uppercase SHA256 values, canonical positive Unix seconds, time window of at least 60 seconds and at most 24 hours, and a supported RSA 2048–4096 key. The maintained .NET `RSA.VerifyData` with SHA256/PSS authenticates original bytes before the seal is interpreted. The seal scope and witness SHA are bound exactly. Afterwards the existing independent ADR 0033 witness verifier checks the ORIGINAL signed witness and rechecks all V017 scope rows under a PostgreSQL **REPEATABLE READ READ ONLY** owner-only transaction.

A successful observation contains only `UNAPPROVED/TEST_HIGH_WATER_SEAL_EXTERNAL_CUSTODY_UNPROVEN`, witness and seal SHA256 and matched-row count. No trust boolean, public signing key or root, raw manifest, credential, tenant grant, time evidence, or authorization is emitted.

## Real PostgreSQL COPY fixture, limits and threat demonstration

The live PostgreSQL 17 xUnit suite `MdsSealedHighWaterCopyRestorePostgresTests`:

- Inserts a disposable V017 checkpoint (no global production issuer), **exports its real row via `COPY (SELECT ...) TO STDOUT (FORMAT CSV)`**, preserving the exported CSV in the test process.
- Advances the checkpoint to a later candidate serial/digest, signs a newer witness and seal with ephemeral *separate* RSA test keys, and holds the SHA256 of that newer seal in the independent test process.
- Deletes that one test policy partition and **imports the older exported bytes via `COPY ... FROM STDIN (FORMAT CSV)`** to simulate rollback of real PostgreSQL table rows. The newer witness fails against the restored lower serial; a previously correctly signed old witness+old seal ALSO fails when the retained latest seal SHA256 remains unchanged.
- Shows the **critical unresolved replay**: if the adversary substitutes the older *latest-seal pin* as well, the old valid test witness and restored rows can return `UNAPPROVED`. A correctly verified signature cannot prove which manifest is the latest without an externally protected, monotonic pin.
- Denies same-version equivocation, wrong RSA seal authority SPKI, wrong latest-seal digest, forged/damaged/expired/noncanonical signed seal, bad witness signature and unprivileged PostgreSQL readers.

This is a real **PostgreSQL scoped COPY data-export/data-import test**, **not a `pg_dump/pg_restore` of the whole database**, point-in-time recovery, true cluster backup restore, multi-region consistency, independently signed production root or immutable external store. It is a strong regression test of conditional rollback detection, not operational durability.

## Work still blocking production

#64 must implement and audit an external **authoritative immutable monotonic latest-seal witness**, signing authority independent from the PostgreSQL and application administrators, approved key custody/rotation and root bootstrap, trustworthy time, failure/outage handling, full PostgreSQL backup/restore tests and split-brain/cloud/offline reconciliation. A caller-supplied pin can be replaced. #57/#55 additionally require independently sourced FIDO Alliance R46 and correct transitional R3 cross-cert handling, full signed MDS JWT chain and issuer-scoped all-hop revocation/CRL/OCSP, status/AAGUID manufacturer policies, CAB/DPIA. Real reviewer-held WebAuthn registration, registrar/approver live authorization and atomic SQL decision remain blocked in #53/#44/#50/#46/#38. V015/V016 SQL interlock and suspended registrar CLI are unchanged.

## Deployment and source references

No new SQL migrations (V017 remains latest), new SQL grants, network access, cloud-only dependency, API/CLI command, production credential or signing key. The exact same testable .NET component can run in OSS on-prem and Azure, but neither is approved to trust its result.

- [ADR 0034](../adr/0034-test-only-sealed-high-water-witness-and-scoped-copy-restore.md)
- [ADR 0033 signed witness](MDS_CRL_SIGNED_WITNESS_RECONCILIATION.md)
- [PostgreSQL 17 COPY](https://www.postgresql.org/docs/17/sql-copy.html)
- [Npgsql COPY](https://www.npgsql.org/doc/copy.html)

## From scoped COPY to full logical PostgreSQL archive regression (#66)

Companion [ADR 0035](../adr/0035-test-only-full-logical-pg-dump-restore-vs-signed-seal.md) and [runbook](MDS_CRL_FULL_PGDUMP_RESTORE_TEST.md) add a separate mandatory Docker CI test: `pg_dump -Fc` of the **entire** disposable TemporalMark PostgreSQL database, then `pg_restore` to a second new database (same PostgreSQL server) with ACLs preserved and 17 migration history entries checked. It reuses **the same** ADR 0033/0034 signed-witness cryptography and read-only snapshot verifier against old restored serial 3 and current serial 4; the test latest-seal hash remains only in its own CI process. This is not a physical backup or independently held immutable witness: an operator substituting old database + old seal + old latest-pin can still induce merely `UNAPPROVED`. #64/#61 and official R46/CRL trust #57/#55 stay open; no new SQL grants, eIDAS, WORM or active WebAuthn credentials.
