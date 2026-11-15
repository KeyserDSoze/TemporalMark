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
