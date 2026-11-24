# QTSP / TSA audit readiness register (initial)

**Status: NOT QUALIFIED.** This file is a development gap register, not a legal opinion or a CAB certification.

The source document supplied with the project is *Diventare QTSP in Italia per un servizio di marca temporale su Azure* (16 pages). Its diagram on pp. 7–8 proposes edge/orchestration/TSU/HSM/UTC/evidence layers; pp. 8–11 define a proposed registry and hourly manifest; p. 12 lists validation checks. Its suggested JSON schema and retention architecture are proposals, not regulations. The diagram on p. 5 is an illustrative timeline, not a committed schedule.

## Applicable primary references (verify current editions with CAB before baseline freeze)

| Reference | What it governs | Evidence needed | Status |
|---|---|---|---|
| eIDAS 910/2014, as amended by 2024/1183, arts. 19–24, 41–42 | TSP governance and qualified electronic timestamps | service definition, policies, incidents, qualified status | Gap |
| Commission Implementing Regulation (EU) **2025/1929** | Qualified timestamp accuracy and binding; refs EN 319 421 V1.3.1, EN 319 422 V1.1.1 | TSU controls, time traceability, test results | Gap |
| Commission Implementing Regulation (EU) 2025/2162 | CAB accreditation, assessment scheme and CAR | CAB scope, CAR, remediation | Gap |
| Commission Implementing Regulation (EU) 2025/2530 | Qualified TSP requirements | organizational/technical proof | Gap |
| ETSI EN 319 401; EN 319 421; EN 319 422; TS 119 312 | TSP security; TSA policy; token profile; algorithms | control-to-test map and signing evidence | Gap |
| RFC 3161 | Request/response wire protocol | DER interoperability and negative tests | Planned |
| AgID/CAD art. 29 and current qualification rules | Italian procedure | CAR, policies, organization, insurance, ISO scope, documentation | Gap |
| GDPR and applicable retention rules | Data protection and preservation | RoPA, DPIA if needed, DPA, lawful retention schedule | Gap |

**Important source update:** the accompanying PDF refers to 2025/2162 and 2025/2530; it omits the **timestamp-specific** implementing regulation 2025/1929. Use all relevant acts, not just those two.

## Release gates — all must be evidenced before claim of own qualified TSA
1. Licensed legal entity / governance and correct registered service scope; assigned accountable personnel, supply-chain controls, independently reviewed CPS/TSA PS/PDS, incident/BCDR/cessation policies.
2. Accredia-authorized CAB with **current** relevant accreditation scope, completed assessment, CAR and corrective actions.
3. AgID procedure completed and **provider + specific timestamp service confirmed on the EU/Italian Trusted List**.
4. HSM suitability and certificate EKU `id-kp-timeStamping`, TSU key ceremonies, single active signing key per TSU, dual control, backup and compromise playbooks.
5. UTC(k) traceability, declared accuracy, independent calibration and timestamp emission halted on desync/expiry/compromise, with evidence.
6. RFC 3161 interop/validation including messageImprint, nonce, CMS signature, revocation and historical Trusted List status, policy and time accuracy.
7. Immutability/WORM, evidence manifests, security logs, tenant separation, recovery/restore and incident exercises, vulnerability testing and independent audit of exports.
8. ISMS/QMS, ISO and insurance obligations as confirmed under current AgID rules; verified contractual arrangements with cloud/outsourcing providers.

## Italian Trusted List verification — 2026 certificate rotation

AgID published new Trusted List signing certificates `IT_tsl5.cer` and `IT_tsl6.cer`, usable from 10 February 2026. Production verification must authenticate the signed Italian TSL with currently accepted keys, handle certificate rollover, preserve historical status snapshots and prove the **specific service** was qualified at issuance time. Merely fetching the current XML or accepting an issuer certificate is insufficient.

Official source: https://www.agid.gov.it/it/notizie/firma-elettronica-qualificata-aggiornati-i-certificati-la-verifica-della-lista-dei ; TSL distribution: https://eidas.agid.gov.it/TL/TSL-IT.xml .

## Evidence register conventions
For each normative control record: `controlId`, regulation/edition/clause, owner, implementation path, automated test, external report URL, auditor approval, last reviewed UTC, risk and remediation ticket. Never mark a control 'compliant' only because a file exists.

## Authoritative links
- https://eur-lex.europa.eu/eli/reg_impl/2025/1929/oj
- https://eur-lex.europa.eu/eli/reg_impl/2025/2162/oj
- https://eur-lex.europa.eu/eli/reg_impl/2025/2530/oj
- https://eur-lex.europa.eu/eli/reg/2014/910/2024-10-18/eng
- https://www.agid.gov.it/it/piattaforme/firma-elettronica-qualificata/prestatori-servizi-fiduciari-qualificati
- https://www.agid.gov.it/it/piattaforme/eidas/marche-temporali-verso-eidas
- https://www.rfc-editor.org/rfc/rfc3161
- https://www.etsi.org/deliver/etsi_en/319400_319499/319421/01.03.01_60/en_319421v010301p.pdf

Before CAB engagement, verify authoritative consolidated legal text, AgID rules currently in force, CAB scope, NIS2 applicability and current ETSI editions. Do not treat prices/timelines in the uploaded PDF as binding.


## Pilot read-side qualified-state assertion interlock (#156)

Although `timestamp_registry.validation_state` structurally permits future `VerifiedNonQualified`, `VerifiedQualifiedExternal`, `VerifiedQualifiedOwn` and `AffectedByIncident`, the **only currently implemented issuer** stores `Unverified`; the system has no independently approved, legally governed verification/status-transition or incident adjudication workflow. Matching TSR SHA256 to retained DER alone proves local byte consistency, not qualified service status at issuance, trustworthy UTC, EU Trusted List history or legal custody. [ADR 0121](../adr/0121-pilot-registry-unsupported-validation-state-read-gate.md)/[#156](https://github.com/KeyserDSoze/TemporalMark/issues/156) therefore fail-close pilot **Page, document-SHA256 Search, Receipt and ZIP read outputs** when a returned row is not exactly `Unverified`; it does not silently downgrade database evidence. [real .NET Business TDD RED 44970125295](https://github.com/KeyserDSoze/TemporalMark/actions/runs/44970125295) on actual .NET10 test-only commit proved 16 unsupported-states incorrectly admitted /264 previous Business tests passed. Parent #13 compliance/CAB, #15 QTSP, #17 signed WORM and #64/#61 custody remain OPEN: this is an output-safety interlock only, **not eIDAS qualification or certification**. Future verified or incident state transitions require explicit independent approval and new ADR/test evidence.


## Pilot new-append qualified/incident label safety (#178)

In addition to the existing **read-only** unsupported-state interlock (#156), [ADR 0136](../adr/0136-pilot-new-append-unverified-state-only.md) forbids **new** app-owned PostgreSQL pilot registry appends unless `validation_state == Unverified`. The caller cannot establish `VerifiedNonQualified`, `VerifiedQualifiedExternal`, `VerifiedQualifiedOwn` or `AffectedByIncident` merely by providing a Domain record or an upstream provider name. Real PG17 [test-only RED](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45181338329) demonstrated exactly four missing status denials; the app admission change followed RED. Existing retained/historic data and future enum/schema support are not rewritten. This rule is **not** a validation of CMS, EU Trusted List status at issuance, legal incident handling, independent WORM/retention, CAB assessment, AgID status or eIDAS qualification; #13/#15/#17 remain open.


## Direct new-write SHA-256 imprint metadata consistency (#179, ADR 0137)

New pilot registry appends via `PostgresTimestampWriter` now require the exact operator-independent SHA-256 algorithm OID and a 32-byte canonical standard padded Base64 document imprint, matching the earlier issuer ingress and the tenant-only exact-imprint lookup. [ADR 0137](../adr/0137-sha256-canonical-new-append.md) was committed before the test-only real PostgreSQL17 [RED 45190099121](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45190099121): 10 unsupported original metadata variants were admitted despite 297 passing tests. The writer guard was added only after that RED. Domain historical data/V001–V020 and future approved algorithm profiles remain unchanged. **Byte-canonical metadata is not RFC3161 CMS `messageImprint` signature verification, certificate/CRL trust, historical EU Trusted List status, WORM retention, independent qualified service assessment, CAB/AgID or eIDAS qualification.** #13/#15/#17 remain OPEN.


## Legacy pilot imprint read metadata interlock (#180)

An authorized registry owner might encounter a V001 legacy/restored `Unverified` receipt whose retained DER SHA256 is locally consistent but whose **document** imprint algorithm OID or Base64 encoding is noncanonical. [ADR 0138](../adr/0138-legacy-canonical-imprint-read-gate.md) fail-closes Page, exact Receipt, Export and Search including lookahead rather than displaying inconsistent metadata or silently modifying historic evidence. Actual test-only [real PostgreSQL17 RED 45195153594](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45195153594) (12 denials missing) and [Business RED 45197067561](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45197067561) (15 missing + 1 lookahead priority; 334 passing) preceded implementation. It reuses the exact SHA256-only **pilot** syntax helper from the new-write gate; future legitimate RFC3161 hash algorithms require independent approved design. This is **metadata self-consistency**, not signed CMS `messageImprint` verification, EU Trusted List service qualification, immutable WORM custody, CAB/AgID/eIDAS approval or a compliant indefinite-retention decision. Parent #15/#17/#13 and independent signed witness #61/#64 remain OPEN.


## Pilot legacy blank PolicyOid read refusal (#181 / ADR 0139)

[ADR 0139](../adr/0139-legacy-policy-nonblank-pilot-read-gate.md) adds a **read-only, tenant-scoped, nonblank policy metadata** guard on historical owner-restored `Unverified` Page/Search/Receipt/ZIP evidence. This closes a gap with the strict offline ZIP v1 verifier and with already strict new-write admission: old SQL schema's NOT NULL policy text alone did not prohibit empty/whitespace-only values. Source change `1ff8c5f7` followed independently observed real PostgreSQL17 [RED 45202036295](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45202036295) and Business [RED 45202193018](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45202193018), preserving all historical raw values, V001–V020, tenant boundaries and 16KiB budget. **Nonblank `PolicyOid` is not evidence of a valid OID string or a signed TSTInfo policy, RFC3161/CMS signer binding, historical EU Trusted List qualification, revocation, independent WORM retention, CAB/AgID or eIDAS status.** Continue independent governance under #15/#17/#13.


## Source field `PolicyOid`/`ProviderId` nonblank parity with offline ZIP (#182)

[ADR 0140](../adr/0140-python-dotnet-pilot-source-nonblank-parity.md), verified real [PG17 RED 45207944794](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45207944794) (10 missed denials) and [Business RED 45208375361](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45208375361) (12 missed denials) preceded code `bbc60c06`: both **new** issuance/direct writer and historical authorized registry reads reject original `PolicyOid` or `ProviderId` that contain *only* U+001C–U+001F Python-whitespace separators (or a mixture with ordinary Unicode whitespace). This aligns source metadata with the current strict Python offline v1 `strip` check without trimming, modifying historical V001 evidence, introducing Azure-only dependencies or relaxing the accepted 16KiB text budget. The two added Python checker tests already passed 36/36 in RED stage. Nonblank source text is **NOT** cryptographically verified CMS `TSTInfo.policy`, issuer certificate/CRL or historical EU Trusted List qualification; it does not prove eIDAS-qualified timestamps, immutable WORM custody, independent signed chain, data-retention legitimacy or approved CAB/AgID status. These legal and evidence gates remain OPEN (#15/#17/#13/#61/#64).


## Unqualified pilot ZIP deterministic ordering, not signed chronology (#183)

[ADR 0141](../adr/0141-canonical-order-pilot-v1-export.md) aligns authorized synchronous `ExportZipAsync` with existing PostgreSQL `ORDER BY issued_utc,id` and Page/Search order checks; a buggy export repository is now refused **before generating** a manifest/ZIP. The standalone verifier independently requires strictly increasing 100ns UTC issuance timestamp and RFC UUID pairs in manifest rows and physical `manifest.json`/TSR member order. Original receipts, source SHA256, tenant scoping, all V001–V020 migrations and identical Azure/on-prem code remain unchanged. Compiled real [Business RED 45213625388](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45213625388/attempts/1) (2 misses, 383 passes) and Python [RED 45214033663](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45214033663/attempts/1) (5 misses, 37 passes) preceded `fd4011ee` source. Deterministic format **does not certify a signed time source or complete-period coverage**. A malicious party can consistently replace both unsigned DER/manifest; retention, independent WORM/legal archive, signer/CRL/EU Trusted List QTSP qualification, signed CMS policy/binding, CAB/AgID and eIDAS approval remain OPEN (#17/#15/#13/#61/#64).


## Offline unqualified v1 original registry text-byte limits (#184)

The current app/PG17 pilot exporter already enforces **16KiB original UTF8 bytes per** `HashAlgorithmOid`, `DigestBase64`, `PolicyOid`, `ProviderId` field and **2MiB across all such fields in the batch** under [ADR 0134](../adr/0134-registry-metadata-text-prewire-budgets.md). [ADR 0142](../adr/0142-offline-v1-original-metadata-utf8-budget-parity.md) extends **only the standalone offline current-v1 ZIP consistency checker** to reject an otherwise self-consistent unsigned ZIP outside the same source-value budgets. Accepted ADR first, real [GitHub test-only Python RED 45218544666](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45218544666/attempts/1) **6 missing denials / 43 passing**, then [source `3d4ec8ab`](https://github.com/KeyserDSoze/TemporalMark/commit/3d4ec8abf276a8210fd97090474da33f79e298cd); original fields, evidence and SQL/V001–V020 unchanged. These byte limits are **operator-defined unqualified pilot resource constraints, not RFC3161 or eIDAS textual requirements**, and do not establish signed CMS/qualified policy binding, QTSP Trusted List status/CRL, independent WORM custody, complete export, lawful indefinite retention or CAB/AgID certification. Parents #17/#15/#13 remain OPEN.


## Deterministic central-directory layout of unqualified v1 ZIP (#185)

[ADR 0143](../adr/0143-offline-v1-central-directory-canonical-order.md) narrows the **standalone offline checker** to the actual v1 .NET ZIP producer's original central-directory record order, which must equal the chronological manifest and local physical member order. Independently observed [test-only RED 45221961848](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45221961848/attempts/1) had 3 missing denial failures / 50 passes out of 53; one-file source [`f1b6d1ce`](https://github.com/KeyserDSoze/TemporalMark/commit/f1b6d1ce6145ab29208265b814404331905437fb) followed only after genuine RED. It does not change original TSR/DER, ZIP manifest content, SQL, online issuer or Azure/on-prem interoperability. Neither ZIP ordering nor local SHA-256 hashes constitutes a signed evidence seal, trust-chain/QTSP historical EU Trusted List verification, signed CMS `messageImprint` validation, WORM legal custody, complete-period attestation, GDPR retention authorization, CAB/AgID or eIDAS qualification. Parent #17/#15/#13 remain OPEN.


## Tenant API response HTTP-cache privacy gap (#186 / ADR 0144)

The current unqualified pilot's Workbox CacheStorage exclusion does not control browser HTTP/proxy caches. Authenticated `/api/v1/me`, `/stamps` list/summary/daily and `/audit` convey tenant or subject metadata; previously only selected TSV/TSR/ZIP/search responses explicitly set `Cache-Control: no-store`. [ADR 0144](../adr/0144-api-v1-uniform-no-store-http-cache-policy.md) adds a uniform versioned-API final header boundary, with no auth or historic data changes. Genuine [signed-Keycloak A/B PostgreSQL HTTP RED 45228057175](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45228057175/attempts/1) identified **18 private/error response types lacking no-store**, despite successful live PG17/restore/browser tests; minimal API middleware [`17babdb9`](https://github.com/KeyserDSoze/TemporalMark/commit/17babdb9e1c3789ca3215f280a615564d26d5329) followed only AFTER real RED. This is a privacy safeguard **for compliant future HTTP caches**, not GDPR purpose/retention/DPIA authorization, erasure of old copies, external CDN/Azure edge verification, signed WORM custody, RFC3161/CMS/EUTL QTSP certification or an eIDAS-qualified timestamp. #115/#113/#20 and #17/#15/#13 remain OPEN.


## Scoped delegated-issuance HTTP input-size denial (#187 / ADR 0145)

The pilot's SHA256 digest issuance endpoint accepts only a canonical Base64 **44-character** imprint (not the document). Its earlier unbounded HTTP JSON input could contain large ignored payload while the separate imprint-search route already had a strict pre-auth 4KiB Kestrel cap. [ADR 0145](../adr/0145-exact-issuance-post-preauth-body-budget.md) adopts an **independent** exact issuance `POST` 4096-byte body budget, Kestrel read limit for chunked input, and fixed private 413/no-store denial, preserving all tenant OIDC authorization and unqualified timestamp semantics. Actual real [test-only signed-Keycloak RED 45408482970](https://github.com/KeyserDSoze/TemporalMark/actions/runs/45408482970/attempts/1) documented a signed 4097-byte issuance returning HTTP 503 rather than 413 after valid signed 4096-byte 503; [source `3f33afad`](https://github.com/KeyserDSoze/TemporalMark/commit/3f33afad755089a3685181d9201623b20d529fe0) followed only AFTER genuine RED. This is a small **local pilot resource-security** step, not RFC3161/CMS/QTSP historical Trusted List validity, independent legal WORM custody, GDPR-approved retention or CAB/AgID/eIDAS qualification. #15/#115/#17/#13 stay OPEN.
