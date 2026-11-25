# ADR 0147 — Fiscal preservation bounded context and release gates

Status: Proposed (review required). Epic #190; implementation starts with #191/#192.

## Context
TemporalMark currently transmits only a SHA-256 imprint, stores pilot RFC3161 receipts as Unverified and cannot establish qualified trust or fiscal preservation. Azure storage/network references do not establish actual immutable evidence custody.

## Decision
Introduce a separate opt-in Fiscal Preservation mode for Italian private-sector expense supporting documents; preserve existing Timestamp Only mode and independent OWN_QTSP track. Azure hosts the preservation service; external QTSP supplies qualified signatures/timestamps when required. Azure is infrastructure, not a legally responsible conservator. PA services, qualified preservation claims under eIDAS, and autonomous qualified TSA issuance are excluded.

Use existing DDD boundaries, tenant selection and database role controls. Add Documents, Signatures and Preservation contexts; integrate existing Stamping through explicit version-bound evidence, never change existing Unverified rows implicitly. A document version is identified by tenant, server-generated document/version ID, exact byte hash and immutable object version. OCR is a separate derivative. All transitions are server-controlled, audited and replay-safe; source class unknown or analog unique without required authentication cannot proceed. Idempotency and reconciliation are mandatory for remote signing, timestamps and durable package creation.

Preservation completion requires independently verifiable package evidence, not a timestamp or accepted deposit alone. Paper-disposal eligibility is disabled until written legal/operational approval and per-document evidence; physical destruction remains a customer decision, never automated. No real fiscal data, production endpoints, changes to V015/V016, state relabeling or irreversible WORM lock in this scaffold.

## Consequences
Review current AgID annexes and applicable SInCRO specification with legal/records specialists before freezing package formats or signing profiles. Governance, retention and privacy precede locks. Use current #14/#15/#17/#18/#113/#115 work; no relaxation of existing controls. External QTSP use is not TemporalMark qualification. Do not advertise compliant fiscal preservation based on an ADR or green tests.

## References
- CAD arts. 22/44: https://www.normattiva.it/uri-res/N2Ls?urn:nir:stato:decreto.legislativo:2005-03-07;82
- DM 17 June 2014 arts. 3/4: https://def.finanze.it/DocTribFrontend/getAttoNormativoDetail.do?ACTION=getArticolo&codiceOrdinamento=200000300000000&id=%7B87979C70-5A4A-4AC6-9743-733088F3D83D%7D
- AgID current documents/annexes: https://www.agid.gov.it/it/piattaforme/sistema-gestione-procedimenti-amministrativi/documento-informatico
- AgID FAQ: https://www.agid.gov.it/it/domande-frequenti/conservazione
- eIDAS: https://eur-lex.europa.eu/eli/reg/2014/910/2024-10-18/eng
