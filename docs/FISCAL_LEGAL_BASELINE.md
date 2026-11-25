# Fiscal legal baseline v0.1 — research candidate, 2026-11-26

#191 / F01, #201 / F11. NOT legal approval. All production claims and paper-disposal eligibility remain disabled. Initial scope: private Italian employers and expense supporting documents; PA, issuance of fiscal receipts, accounting deductibility determination, qualified preservation and own QTSP excluded.

## Source register (review current effective text before release)
- L01: CAD, d.lgs. 82/2005 art. 1(1)(v), 22 and 44; [art. 22 consolidated text](https://docs.italia.it/italia/piano-triennale-ict/codice-amministrazione-digitale-docs/it/v2026-04-20/_rst/capo2_sezione1_art22.html). Distinguish source provenance, copies and document custody. An analog non-unique original is not inferred from extension or OCR; content must be reconstructible from other records subject to mandatory retention, including records held by third parties.
- L02: [DM 17 June 2014 art. 4](https://def.finanze.it/DocTribFrontend/getAttoNormativoDetail.do?ACTION=getArticolo&articolo=Articolo+4&codiceOrdinamento=200000400000000&id=%7B87979C70-5A4A-4AC6-9743-733088F3D83D%7D). Applicable signature for analog-copy generation; unique original requires authorized public-official authentication of conformity; physical destruction only after completion. No universal assumption of per-receipt timestamp or QES for native digital originals.
- L03: [DM art. 3](https://def.finanze.it/DocTribFrontend/getAttoNormativoDetail.do?ACTION=getArticolo&codiceOrdinamento=200000300000000&id=%7B87979C70-5A4A-4AC6-9743-733088F3D83D%7D). Fiscal search/retrieval fields, temporal reference on archive package and statutory deadline cross-reference; actual deadline computation must be approved by tax counsel per tax period/document class.
- L04: [AgID guidelines and annexes](https://trasparenza.agid.gov.it/page/29/details/38/linee-guida-sulla-formazione-gestione-e-conservazione-dei-documenti-informatici.html), [conservation FAQ](https://www.agid.gov.it/index.php/it/domande-frequenti/conservazione). Private-sector applicability, roles, packages and manual. Confirm currently effective editions, annexes, SInCRO profile and applicable metadata with a records specialist; no claim of conformity by storage configuration alone.
- L05: [Agenzia Entrate resolution 96/E, 21 July 2017](https://def.finanze.it/DocTribFrontend/getPrassiDetail.do?id=%7B02517330-96E8-4E34-BDB7-C1EA7A7AE801%7D); [regional public archive summary of response 142, 24 June 2024](https://poloarchivistico.regione.emilia-romagna.it/notizie/archivio-news/news-2024/dematerializzazione-delle-note-spese-agenzia-entrate-fa-chiarezza). Case-specific guidance: faithful digitization, unique/non-unique classification, and tax deductibility requirements remain distinct. A generic card-payment receipt is not necessarily sufficient proof of a taxi expense. No general product approval inferred.
- L06: eIDAS arts. 41/42 and GDPR: see FISCAL_PRESERVATION_CONTROLS.md. Qualification belongs to specific listed services; retention/processing require review.

MEF article search extracts retrieved; direct detail fetch returned HTTP 502 during research. Recheck full texts and current provisions before counsel sign-off. 142/2024 referenced through public archive summary; obtain original and verify exact scope before legal freeze.

## Provisional classification / denial rules
| Input | Candidate class | Pilot handling | Future prerequisite |
|---|---|---|---|
| Native digital supplier document | NativeDigital | Record unapproved source assertion only | prove provenance, retain original bytes, apply relevant preservation rules |
| Paper receipt with independently established mandatory retained counterpart | AnalogNonUnique | Record unapproved assertion only | approved classification, faithful copy and applicable signature |
| Paper receipt without established counterpart | AnalogUnique or Unknown | block automatic progression | authorized public-official authentication if unique and legally eligible |
| Unclear origin or only OCR output | Unknown | deny fiscal progression | human review of original and documented classification |
| Unsupported / prohibited category | Excluded | deny fiscal progression | explicitly revised approved policy, not a bypass |

All classes: no fiscal release, no deletion of paper, no implicit verification based on SHA-256, timestamp, upload, OCR or deposit acceptance. Pilot classification is not legal adjudication. Human/organizational authorization and exact-version evidence must later be proven by F04/F07/F13. No physical destruction automation.

## Responsibility boundaries (candidate)
Customer: lawful document classification, accounting/tax treatment, adoption of manual and responsible-for-preservation role, paper retention decision.
TemporalMark operator: service preservation process, integrity, package evidence, access/exit, operational roles, incidents and contract-defined tasks.
External QTSP: specific trust service and issued evidence.
Microsoft Azure: contracted cloud/subprocessor infrastructure; not the preservation decision maker.
Legal/records reviewers: approve scope, signing profile, metadata, deadline rules, exceptions and evidence before release. Named role assignments and legal allocation remain open in #201.

## Acceptance evidence still missing
- Named qualified tax and records reviewers; written approval of examples, applicable signatures, unique-original and exception rules.
- Exact legally applicable retention and deadlines (including holds); manual, contracts, data protection and RACI.
- Verified source-class decision workflow and independently verified preservation completion.
- Release authorization #203. Keep #191 OPEN; this is desk research, not sign-off.
