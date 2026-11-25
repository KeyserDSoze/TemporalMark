# TemporalMark Fiscal — execution roadmap

**PROPOSED / NOT FISCALLY COMPLIANT / PAPER DISPOSAL DISABLED.**
Parent #190. Scope: Italian private-sector expense receipts and supporting documents. No PA or own QTSP qualification. No actual customer documents or personal identifiers in this public repository or CI. Use synthetic fixtures until authorized pilot.

## Work packages
| ID | Issue | Delivery |
|---|---|---|
| F01 | #191 | Legal scope and source-class/control matrix |
| F02 | #192 | Domain and lifecycle |
| F03 | #193 | Document capture and private Blob custody |
| F04 | #194 | Copy conformity and signature |
| F05 | #195 | External QTSP and historical trust |
| F06 | #196 | WORM and signed evidence |
| F07 | #197 | PdV/RdV/PdA/PdD and applicable SInCRO |
| F08 | #198 | Orchestration and reconciliation |
| F09 | #199 | Portal, OCR, search and exhibition |
| F10 | #200 | Long-term readability/integrity and renewal |
| F11 | #201 | Governance, manual, retention/GDPR |
| F12 | #202 | Real Azure rollout and independent assurance |
| F13 | #203 | Final release and paper-disposal eligibility |

F01 first; F11 in parallel. F02/F03/F05 form core engineering track. F04 and F06 depend on approved copy/trust/retention policy; F07/F08 bind all evidence; F09/F10 deliver exhibition and maintenance; F12 validates runtime; F13 is last. Reuse #14/#15/#17/#18/#113/#115; own QTSP #13/#16 is independent.

## Target structure (initial directory markers, not executable implementation)
- Domain: Documents (source and version), Signatures (conformity evidence), Preservation (packages, state).
- Business: Documents (capture/review), Signatures (provider abstraction and validation), Preservation (orchestration and release policy).
- Infrastructure: AzureBlobStorage (real data plane), Signatures (external adapters), Preservation (index/format and evidence adapters); trust list extension of Stamping #15.
- API/UI remain unchanged until TDD implementation; existing project dependencies and migration history unchanged.

## Candidate workflow
Quarantined -> Acquired -> Reviewed -> CopyRequirementsSatisfied -> Submitted -> DepositAccepted -> PreservationCompleted -> eligible for customer review under approved policy only. Rejection, incident, unknown classification, validation failure and incomplete evidence block the release. State names are proposals. A native digital document may not need the analog-copy signature step; F01 defines the applicable requirements. A deposit acceptance is not archive completion. Individual timestamps are not presumed mandatory for every receipt: F01/F05/F07 determine the necessary profile, including package-level temporal reference.

## Release policy
All controls in FISCAL_PRESERVATION_CONTROLS.md require source/edition, owner, tests, evidence and reviewer. No control satisfied by a file alone. Do not enable fiscal claims or disposal in code until F13. For each implementation slice follow ADR -> RED -> implementation -> negative tests -> exact-head CI -> evidence link. Existing unqualified pilot states and registrar interlocks stay intact.
