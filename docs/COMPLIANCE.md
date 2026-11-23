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
