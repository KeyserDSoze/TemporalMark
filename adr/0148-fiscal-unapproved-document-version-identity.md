# ADR 0148 — Unapproved fiscal document version identity (first TDD slice)

Status: Proposed; #192, depends on #191 approval for any production policy.

## Scope
Only a pure domain value object for synthetic pilot document versions. No API, persistence, schema, credentials, storage or legal classification. Explicit immutable tenant, document and version IDs, canonical lowercase SHA-256 hexadecimal digest, positive byte count, UTC acquisition time and declared source classification (Unknown, NativeDigital, AnalogNonUnique, AnalogUnique, Excluded). Unknown and Excluded may be recorded as unapproved metadata; all classes remain unapproved. Invalid enum values reject. Require nonempty IDs. No physical disposal method or enable flag: PaperDisposalEligible is always false at this stage. RequireTenant checks supplied server-authorized tenant against immutable owner; this is a defense-in-depth domain check, not authentication. Corrections create a separate version later; never mutate current version identity. No legal timestamp or proof of source asserted by local clock/hash. No public setters, no mutable byte buffers.

## Tests first
Compile against the existing domain using a reflection-based contract test to ensure a missing type is an explicit failing assertion (rather than compilation failure). Then use reflection only for this initial contract; follow with strongly typed tests once implementation exists and RED has been observed. Reject empty IDs, invalid hash/size/time/class, cross-tenant access, and assert disposal false for all classes. No actual document bytes or customer data. No implementation before recorded RED under existing delivery discipline. CI triggers only main push/manual dispatch; do not alter CI or merge a knowingly failing slice to obtain RED.

## Next increment
After witnessed RED, introduce the immutable value object; then test exact-head CI. F01 still requires legal approval before classification progression. State transitions, replay, correction lineage, tenancy integration and forward-only migration remain separate #192 sub-slices.
