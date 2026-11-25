# TemporalMark Fiscal — preservation manual working draft v0.1

**DRAFT / NOT ADOPTED / NOT A SERVICE AUTHORIZATION.** F11 #201, F01 #191, F13 #203.
This is an operational design and approval checklist, not a claim of compliance. No real customer documents, irreversible retention locks, fiscal completion or disposal eligibility until the relevant approvals. Customer-specific manual/contract and named appointments must be adopted outside this public repository.

## 1. Scope and references
Italian private-sector expense supporting documents only; classification and applicable copy/signature rules are pending F01. No PA, fiscal receipt issuance, tax deductibility decision, qualified preservation or own QTSP claim. Current hash-only pilot remains independent. References: [AgID conservation FAQ](https://www.agid.gov.it/it/domande-frequenti/conservazione), [official guideline and six annexes register](https://trasparenza.agid.gov.it/page/29/details/38/linee-guida-sulla-formazione-gestione-e-conservazione-dei-documenti-informatici.html), CAD art. 44, DM 17 June 2014 arts. 3–4 and GDPR. AgID FAQ confirms private-sector obligations and the independence of an external responsible-for-preservation role from the conservator. Current applicable editions/sections must be confirmed; direct FAQ retrieval returned 403 in this research session, search extracts available. Do not freeze the legal baseline until reviewed.

## 2. Roles and approval boundary (proposed)
R = executes; A = accountable within the indicated operational scope; C = consulted. Legal allocation and appointments must be approved, not inferred from this table. No names/IDs in public source.

| Activity | Customer / holder | Customer's preservation officer | TemporalMark service manager | Security/privacy staff | External QTSP |
|---|---|---|---|---|---|
| Source classification and accounting purpose | A/R | C | C | C | - |
| Adopt customer manual and preservation policy | A | R | C | C | - |
| Intake, rejection and package process | C | C | A/R | C | - |
| External signing / timestamp trust evidence | C | C | R | C | A/R for its own service |
| Monitoring, recovery and exhibition | C | C | A/R | R | C |
| Approve retention and exceptional holds | A | R | C | C | - |
| Customer paper-disposal decision | A/R | C | provides verified evidence | C | - |

The customer retains governance and the legally applicable responsibility of its responsible-for-preservation role. An external officer must be independent of the conservator as required. TemporalMark's service manager and technical/security/archival roles require formal appointments, competence evidence, backups and separation of duties. Azure acts as infrastructure supplier under approved contract and processing terms; it does not approve the preservation lifecycle.

## 3. Document intake and package profile (F02–F08)
Each version binds tenant, document/version IDs, exact original bytes, SHA-256, object version, source class and applicable policy version. Quarantine before admission; explicit rejection with non-sensitive reason, retry and reconciliation. OCR is a separate derivative. Classification is not proven by file extension or hash. Verify required copy/conformity and signature evidence against exact version before submission. Determine accepted formats, maximum sizes, metadata and applicable SInCRO edition in reviewed specifications. Define PdV, RdV, PdA, PdD creation, validation, signatures/reference time, receipt of requests and verification of completed durable archive. Never confuse deposit acceptance with completed preservation.

## 4. System and infrastructure
Existing .NET/PostgreSQL/React, private Azure Container Apps and Blob reference. Actual application managed-identity PUT/GET, network denial, version binding, signed manifest and WORM verification are mandatory operational evidence (#193/#196/#202). Database is an index, not sole immutable evidence. Define geographic location and backup/DR approved by contract; no assumption that a region setting proves residency. Segregate identities, privileges and tenant scopes; record all approved changes. No storage account keys, credentials or customer artifacts in GitHub. External provider trust and rollover evidence in #195.

## 5. Retention, legal holds and scarto
No universal/default indefinite retention. Before any irreversible lock, legal/records owner approves per-class policy: legal basis, start trigger, tax/accounting deadline, minimum/maximum period, relevant proceedings/holds, deletion exceptions, backup/log lifecycle, renewal and evidence. Retention policy must be versioned and tenant-bound; unsupported/unknown rules block activation. Legal hold overrides scheduled disposal; release requires authorized documented review. Scarto requires independent review of applicable obligations and verified record of scope/outcome; never automatically delete originals or release a hold merely because a timer elapsed. Test mock and real storage policy behavior, including accidental shortening and tenant isolation, before deployment.

## 6. Access, exhibition and long-term integrity
Define authorization to deposit/search/request distribution; audit without revealing document content to unauthorized operators. Export a complete independently verifiable package in readable formats; test representative fiscal queries, access denial and customer exit. Define documented periodic integrity/readability verification, monitoring and renewal triggers, corrective actions, formats/algorithms migration and retained lineage. Schedule and owners remain unapproved (F10).

## 7. Incidents, continuity, privacy and cessation
DPA and data-flow inventory: distinguish controller/processor roles, approved subprocessors, regions, transfers, access, data subject requests, privacy risk/DPIA assessment and notifications. Define incident severity/escalation, evidence isolation, compromised-key handling, service interruption, backup/restore exercises and customer notification obligations. Approved RPO/RTO, SLAs, recovery and exit runbooks needed; no production promises from this draft. On cessation deliver complete verified export, coordinate holds/retention and approved destruction; prove readability and handover before termination. All customer-specific evidence stays in controlled systems.

## 8. Adoption checklist
- [ ] F01 legal/records approval; classification and signing policy, deadlines and exceptions.
- [ ] Named customer officer, service manager and competent operational/security roles, independence and succession.
- [ ] Customer manual, service manual and contracts/DPA adopted; responsibility split approved.
- [ ] Formats, metadata, package/signature profile, retention/hold/scarto and privacy policy approved.
- [ ] Live Azure/QTSP tests, independent verification, restore/exit and incident drills.
- [ ] Reviewed evidence for each applicable FP control, exact-head CI and independent approval.
- [ ] F13 written release; customer decision remains separate from software eligibility.

No checkbox can be checked solely because this document exists. All decisions remain pending. Store actual approved manual versions, sign-offs, contractual annexes and evidence in controlled private locations.
