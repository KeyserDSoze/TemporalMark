# Offline signed checkpoint witness versus V017 (test-only, #63)

**Status: NOT FIDO TRUST / UNAPPROVED.** This is a deterministic cryptographic and real-PostgreSQL *restore mismatch regression*, not a trusted external witness, not a production anti-rollback service and not an authorization. ADR [0033](../adr/0033-non-authorizing-external-signed-checkpoint-witness-reconciliation.md); parent [#61](https://github.com/KeyserDSoze/TemporalMark/issues/61) and [#57](https://github.com/KeyserDSoze/TemporalMark/issues/57) remain OPEN. V015/V016 registrar issuance and CLI remain blocked.

## What the isolated code checks

The shared .NET 10 `ReviewerMdsOfflineSignedCheckpointWitnessReconciler.ReconcileAsync` takes a pre-opened PostgreSQL owner connection, a **detached signed** witness, the signature, a caller-selected **test RSA public key**, and explicit UTC observation time. It performs only offline `RSA.VerifyData` with SHA-256/PSS, with no internet, HSM, production root bundle, metadata fetcher, SQL writes, CLI, API or enrollment integration.

The witness byte format is strict, canonical ASCII with no CR/NUL/space, and is **signed over its original bytes**:

```text
TEMPORALMARK-UNAPPROVED-MDS-CRL-WITNESS-1
<SOURCE_POLICY_SHA256>
<ISSUED_UNIX_SECONDS>
<EXPIRES_UNIX_SECONDS>
<N>
<ISSUER_CRL|MDS_BLOB>|<ISSUER_KEY_SHA256>|<POSITIVE_SERIAL>|<EVIDENCE_SHA256>
...
```

That is a *structural description*, not a copyable real witness: the domain header must match literally, hash values must be exactly uppercase 64-character hex, serial and count must use strictly canonical positive decimal without leading zeros, and each entry has exactly four pipe-separated fields. There must be a terminal LF, no additional blank/duplicate fields, and entries must be strictly ordered by `kind|issuer_key_sha256`, without duplicate keys. The test profile requires at least one and at most 128 records, manifest at most 64 KiB, RSA key 2048–4096 bits, signed issued/expiration bounded to the current UTC test clock, and lifetime of 60 seconds–24 hours.

Only after signature verification, the component checks the **physical V017 checkpoint table owner session**, begins a PostgreSQL `REPEATABLE READ READ ONLY` transaction and fetches **every row in exactly the signed source-policy partition**. Every listed candidate must be present and identical in kind, issuer SHA-256, serial and content SHA-256. Additional rows in the **same partition**, missing rows, older restored version, equal-version changed digest, newer DB version not reflected in the witness, expired or future-dated DB observations, changed source policy, bad signature and unprivileged SQL roles fail closed. Other source-policy partitions are deliberately outside this witness and are **not** covered. A separate external trusted process would need to define and attest which partitions must exist.

The only positive result is:
- `ReviewStatus=UNAPPROVED`
- `PolicyStage=SIGNED_WITNESS_ONLY_EXTERNAL_CUSTODY_UNPROVEN`
- A SHA-256 digest **of the input witness** and number of structurally matching *untrusted* candidate rows. No raw witness or public key is returned.

Tests use ephemeral RSA-PSS signing keys generated in CI and *real live PostgreSQL V017 tables*. They model an old backup by **directly editing a fixture row** as the migration owner, rather than performing a real `pg_restore` operation. The tests are regression proof for detecting a mismatch **if an authentic latest signed witness is already supplied**. They are **not** evidence of an independently protected external storage device, durable monotonic signing authority, hardware key custody or disaster-recovery readiness.

## Release blockers still open

- The witness public key is **caller-selected** and may be attacker-controlled, and the signed data may be forged. Nothing pins a CAB/HSM-reviewed witness key, or prevents replaying an **old DB backup together with an old signed witness**. A real DR safety protocol must hold the newest signed high-water mark **outside** mutable primary/backup control, verify secure distribution on-prem/offline and Azure, support signed witness root rotation, and test full backup/restore, failover, split-brain and clock rollback.
- The underlying V017 issuer/digest/source-policy fields are **caller claims**, not signed official FIDO MDS JWS, not validated CRLNumber/AKI/CDP, not an attestation leaf trusted by GlobalSign R46, and not verified current statuses. #57/#55 need authentic 2026 R46 x5c cross-chain, all-hop CRL/OCSP and independent CAB review before trust.
- The component is **not atomically joined to a future active signer or issuance action**. A read-only snapshot has a time-of-check/time-of-use race by definition; later independent approved SQL consume and verified reviewer-held WebAuthn identity are needed. There are no new registration grants; #53/#44/#50/#46/#38, and deployment/compliance blockers, stay OPEN.
- This is **not a WORM/eIDAS/QTSP qualification or production evidence-retention service**.

## Operational note

V017 is still the only schema version touched: **no V018 migration** and no reissue of registrar intent. Both on-prem OSS and Azure compile the same isolated code, without mandatory Azure services. No changes to IAM/RP policy, root trust, R3/R46 certificate provenance or credential registration. Real external witness hardware/custody, rollback-safe discovery, offline signing/import audit, and alerting remain #61.

Sources: [PostgreSQL repeatable read](https://www.postgresql.org/docs/17/transaction-iso.html), [.NET RSA.VerifyData](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.verifydata), [FIDO MDS changelog](https://fidoalliance.org/mds-changelog/).
