# MDS/CRL — offline RSA-PSS signed file high-water journal (TEST ONLY, #67)

**NON-AUTHORIZING / UNAPPROVED / NO INDEPENDENT IMMUTABLE CUSTODY.** This is an offline hash-linked, file-backed prototype for the signed latest-seal problem. It is neither a production trusted witness provider nor a FIDO Alliance MDS root, signed CRL trust service, immutable record, independent key escrow, legal evidence retention or disaster recovery solution. See [ADR 0036](../adr/0036-fail-closed-test-signed-file-high-water-journal.md), parent [#64](https://github.com/KeyserDSoze/TemporalMark/issues/64) and [#61](https://github.com/KeyserDSoze/TemporalMark/issues/61).

## Exact test-only protocol

`ReviewerMdsOfflineFileHighWaterJournal` lives in the .NET 10 infrastructure assembly and is deliberately **not** connected to HTTP, API, UI, CLI, registrar issuance or SQL grants. It never generates, stores or exports a private key. The fixture supplies a disposable RSA signer **public key** and separate claimed SHA256 SPKI pin. The file itself is created explicitly by `BootstrapNewForTests` in an already created test-owned directory using **`FileMode.CreateNew`** and exclusive file access. Normal `InspectLatest` and `AppendSignedForTests` calls require a pre-existing valid file. No automatic re-bootstrap when a file is missing or corrupt.

The file starts with three LF-separated ASCII lines: `TEMPORALMARK-UNAPPROVED-SIGNED-FILE-HIGHWATER-1`, a 64-character uppercase-hex claimed source policy SHA256, and the 64-character uppercase-hex claimed RSA signer SPKI SHA256. Every subsequent line is canonical `Base64(original signed payload)|Base64(detached RSA-PSS signature)` and terminal LF, with no extra whitespace or control characters. The original payload is the exact six-field LF-separated ASCII body:

```text
TEMPORALMARK-UNAPPROVED-SIGNED-FILE-HIGHWATER-EVENT-1
<SOURCE_POLICY_SHA256>
<POSITIVE_STRICTLY_INCREASING_SERIAL>
<SEAL_SHA256>
<PREVIOUS_SIGNED_PAYLOAD_SHA256>
<UTC_UNIX_SECONDS>
```

The first event has 64 zero hex digits as the previous hash. Subsequent events must contain the SHA256 of the actual **previous original signed payload**. Every RSA-PSS/SHA256 signature is cryptographically checked against the same caller-selected *test* public key. The source policy, pin, original payload and signature must all match; dates must not go backward, be from the future or have an obsolete latest event. File contents are strictly bounded (128 events, 128 KiB, max 512-byte signed payload, RSA 2048–4096 bits). Version rollback, repeat of equal serial (even equal digest), same-serial equivocation, wrong key/pin, broken hash chain, unsupported byte encoding, oversized/partial file, old event, invalid signature, missing file or empty journal all fail closed.

The file opens with `FileShare.None` on each read and append. A write verifies **the entire previously stored chain** under that lock, then appends a new externally signed record and calls `Flush(flushToDisk: true)`. Abrupt partial writes must be treated as corruption and *never repaired or truncated automatically*. The normal status is always `UNAPPROVED/TEST_FILE_HIGH_WATER_NO_INDEPENDENT_CUSTODY`, with latest synthetic serial, seal SHA256 and payload digest. No result authorizes signer trust or credential creation.

## Tests and a real PostgreSQL full logical restore

The isolated `ReviewerMdsOfflineFileHighWaterJournalTests` xUnit suite generates ephemeral RSA test keys and a temp file; it tests:
- New-file-only bootstrap and absence/fail-closed startup, signed append/reopen/persistence, rejection of equal/lower/divergent serials;
- Invalid signature/pin, forged key, wrong source policy or previous entry hash, missing/truncated/edited file, stale/future clock, malformed fields and bounded record types;
- Two same-version concurrent writers against the same exclusive file; never more than one accepted;
- **Residual attack explicitly demonstrated:** replacing the entire journal with an older, genuinely signed file restores the older *UNAPPROVED* high-water state. File append and signature checks cannot prevent host-administrator rollback.

The mandatory [full logical PostgreSQL `pg_dump/pg_restore` fixture](MDS_CRL_FULL_PGDUMP_RESTORE_TEST.md) now also creates this journal **outside both PostgreSQL databases**, appends old serial 3 and newest serial 4 as independently RSA-signed entries, closes and reopens the file after restoring the old database, obtains the latest test seal SHA256 **from disk**, and verifies that the existing ADR 0034 verifier rejects the correctly signed old witness+seal against that latest value. The test then intentionally restores an older valid journal file to demonstrate the unsolved dual-rollback scenario. All outcomes remain `UNAPPROVED`.

## Explicitly unresolved security/operations

- **Not independently protected:** journal file and signer verification key/pin are created by and controlled by the disposable CI/test process. An OS/root/storage/backup administrator can replace a valid file with a valid older copy, swap trust-root configuration, symlink the path or replace the file between inspection and use. `FileShare.None` is not a distributed lock, strong filesystem sandbox or security separation. `Flush(true)` is not WORM/antirollback or an attested power-loss guarantee.
- **No true external monotonic authority:** real CAB-vetted signer key custody (HSM or equivalent), independently controlled append-only/WORM witness store, offsite latest-pointer pin, safe key rotation, two-person operation, audit, clock/expiry governance, cross-region state machine, compromised-authority response, crash/recovery protocol and on-prem/Azure parity remain open under **#64**.
- **Not full DR:** #66 restores a full *logical database on the same Postgres instance*, not physical cluster backup/WAL/PITR, remote cluster restore, cross-region failover or complete application/Keycloak disaster recovery. No source metadata is upgraded to trust.
- **No FIDO R46 qualification:** genuine independently validated FIDO MDS JWS/x5c and current R3→R46 cross-cert, signer root, CRL/OCSP issuer revocation, AAGUID/firmware status and CAB approval remain release blockers #57/#55/#53. SQL V015/V016 freeze, suspended registrar intent CLI and #44/#50/#46/#38 remain OPEN. No eIDAS/QTSP qualification, WORM retention or activated WebAuthn credential is implied.

## References

- [ADR 0036](../adr/0036-fail-closed-test-signed-file-high-water-journal.md)
- [.NET 10 FileStream](https://learn.microsoft.com/en-us/dotnet/api/system.io.filestream?view=net-10.0)
- [Full logical restore runbook](MDS_CRL_FULL_PGDUMP_RESTORE_TEST.md)
- [FIDO MDS root rollover changelog](https://fidoalliance.org/mds-changelog/)
