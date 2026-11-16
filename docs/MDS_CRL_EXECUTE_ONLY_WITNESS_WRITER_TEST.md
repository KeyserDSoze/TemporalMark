# CI witness PostgreSQL: EXECUTE-only writer and NOLOGIN SECURITY DEFINER role (#70)

**TEST-ONLY / UNAPPROVED / NOT AN IMMUTABLE OR LEGAL WITNESS.** This refines the separate PostgreSQL test witness introduced in [ADR 0038](../adr/0038-ci-only-separate-postgresql-witness-instance.md) and documented in [the existing runbook](MDS_CRL_SEPARATE_POSTGRES_WITNESS_TEST.md). The specific decision is [ADR 0039](../adr/0039-ci-nonlogin-definer-and-execute-only-witness-writer.md). Parent [#64](https://github.com/KeyserDSoze/TemporalMark/issues/64) **remains OPEN**.

## Exact privilege separation in the disposable second PostgreSQL server

There are now FOUR distinct test identities: the `temporalmark_witness_owner` PostgreSQL **superuser** controls the test container/bootstrap; the **NOLOGIN**, **NOSUPERUSER** `temporalmark_witness_data_owner` owns the two SQL tables, generated event identity sequence and the limited writer function; the **NOSUPERUSER** `temporalmark_witness_writer` login has **EXECUTE only** on `record_unapproved_highwater_witness(text,bigint,text)`; the separate `temporalmark_witness_reader` login has **SELECT only** on the latest-checkpoint table and NO EXECUTE of the write function or access to audit events.

The writer cannot act as, or inherit, the data owner. It has no direct table/sequence SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES or TRIGGER rights, cannot create a table in `public`, cannot create a temporary table, and cannot grant itself privileges or CREATE ROLE/DB. The function is intentionally `SECURITY DEFINER`, owned by the restricted NOLOGIN data owner, with `SET search_path=pg_catalog,pg_temp` and **fully schema-qualified** `public.` table operations. Only one hardened entry point enforces positive, strictly increasing candidate serial, uppercase 64-hex policy/seal SHA256, and a same-transaction append-event history row. Equal/older/reused serial, malformed hash or divergent same-version seal always fail closed.

A PostgreSQL function normally has default `PUBLIC EXECUTE` permission, and databases can grant `PUBLIC TEMPORARY`; both are explicitly revoked during the **same SQL bootstrap transaction** that creates the privileged function and roles. No privileges are granted on the first/main application PostgreSQL server, and no V018 migration is created. Only the opt-in `witness-ci` Docker profile is affected; the standard on-premises Compose deployment and Azure Terraform remain unchanged.

## Real TDD and integration coverage

The mandatory `docker-smoke` whole logical main-DB `pg_dump -Fc/pg_restore` regression now passes a third separate test connection string for the writer account. Its SQL fixture:

- Confirms `session_user/current_user` are exactly `temporalmark_witness_writer`, none of its superuser/createdb/createrole/replication flags is set and it has **no membership** in the NOLOGIN data owner.
- Verifies the function is `SECURITY DEFINER` and owned by the NOLOGIN data-owner role; both checkpoint and audit tables are protected from direct SQL by the writer.
- Attempts direct SELECT, DELETE, UPDATE, TRUNCATE, CREATE TABLE, CREATE TEMP TABLE, and `SET ROLE` to data owner: every attempt must be rejected. An authenticated writer can stage signed synthetic serial 3 then 4 only through the definer function; lower/equal/invalid SHA candidates fail without changing the event history.
- Retains the existing independently read-only witness-reader restrictions and separate `pg_control_system().system_identifier` PostgreSQL server proof. After full main DB restore to serial 3, the separate witness remains at serial 4. Original RSA-PSS signed ADR 0033/0034 witness+seal remains **UNAPPROVED** for current main DB and fails when compared against old restored DB.
- Runs the complete four GitHub Actions jobs, including PostgreSQL V017 migration/security regression and Keycloak/OIDC real browser MFA, on the **exact final HEAD of `main`**.

## Crucial limits and release blockers

**This does not eliminate witness superuser access.** The CI Docker host still owns BOTH PostgreSQL servers/volumes, passwords and disposable RSA signer keys. The witness `temporalmark_witness_owner` superuser can rewrite tables/audit, alter the definer function, impersonate ordinary roles or restore an old witness volume. A compromised test writer can submit a bogus *higher* synthetic serial/hash through the function because no independent authorized signer/authenticated provenance or dual-control approval has been provisioned. Thus signed hashes and increasing serials alone do NOT establish an independent latest version, legal WORM store, trusted FIDO Alliance MDS R46 JWS/x5c and issuer CRL/OCSP, authoritative time or approved WebAuthn enrollment.

To close #64/#61, separately administered and independently anchored monotonic witness custody, secure CAB/HSM signer identity/bootstrap/rotation, append-only immutable offsite backup, physical PITR and regional split-brain tests, proven on-prem OSS/Azure parity and appropriate legal/privacy review are still required. #57/#55/#53/#44/#50/#46/#38 likewise remain OPEN. V015/V016 registrar SQL and CLI issuance freeze are not modified; there is no activated credential, eIDAS qualification, QTSP or WORM evidence claim.

Technical sources: [PostgreSQL 17 CREATE FUNCTION](https://www.postgresql.org/docs/17/sql-createfunction.html), [Privileges](https://www.postgresql.org/docs/17/ddl-priv.html), [Default privileges](https://www.postgresql.org/docs/17/sql-alterdefaultprivileges.html).

## CI coverage correction and TDD proof

A retrospective audit found that the prior #69 Docker CI started the second witness container but used a `dotnet test` filter selecting **only** `MdsFullPgDumpRestorePostgresTests`; the separately authored `MdsSeparatePostgresWitnessRestoreTests` was NOT exercised. #69 was formally reopened and the prior success claim corrected on its GitHub issue. The mandatory test command now selects both classes. [RED run 43832267622](https://github.com/KeyserDSoze/TemporalMark/actions/runs/43832267622) ran 2 tests and failed the second with the expected PostgreSQL `28P01` missing writer-login authentication after 1 successful main-restore test, before bootstrap implementation. GREEN additionally prevents shared-fixture class parallelism via a named xUnit collection and restores the synthetic original digest after tamper tests. #69 and #70 must **not** close until the now-executed second-cluster suite and all final SHA jobs pass.
