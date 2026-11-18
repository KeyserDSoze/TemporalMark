# ADR 0066 — RFC 3161 TSA CMS signer end-entity and signing-only Key Usage pilot gate

Status: Accepted for the **unqualified delegated TSA pilot** (2026-11-18). Scoped [#97](https://github.com/KeyserDSoze/TemporalMark/issues/97), child of open [#15](https://github.com/KeyserDSoze/TemporalMark/issues/15).

## Reviewed baseline and normative context

Reviewed ADR 0002 (delegated vs own qualified timestamping), ADR 0058 (sole critical timeStamping EKU) through ADR 0065 (signed issuer CRLNumber floors), the exact ExternalRfc3161TimestampProvider, ExternalRfc3161SignerCertificatePolicy and certificate chain/CRL policies, signer xUnit fixtures, docs/TSA_HTTP_TRANSPORT.md, docs/THREAT_MODEL.md and docs/ROADMAP.md. [RFC 3161 §2.3](https://www.rfc-editor.org/rfc/rfc3161#section-2.3) requires the TSA key be reserved for timestamps and the single critical EKU be exclusively timeStamping. [RFC 5280 §4.2.1.3](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3) distinguishes digitalSignature/contentCommitment from encipherment and certificate/CRL signing. [RFC 5280 §4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9) distinguishes CA basic constraints from end-entity certificates.

Existing CMS signature/imprint/nonce, critical sole EKU, operator-pinned certificate, signed policy, signed live genTime, offline CustomRootTrust issuer chain and separately signed full issuer CRLs do not provide an explicit, auditable **KU/CA profile check** independent from platform-dependent chain-building behavior.

## Decision

1. Add an isolated, narrowly named signer **pilot profile** validation AFTER cryptographic CMS signer identification and existing exclusive critical EKU, BEFORE any verified receipt can be persisted. It does **not** replace signature, chain, nonce, revocation, Trusted List or time checks.
2. Require exactly one parseable end-entity Basic Constraints extension with CA=false and no path-length constraint. Accept critical or noncritical end-entity Basic Constraints. Requiring this extension is an intentionally stricter **TemporalMark interoperability policy**, not a claim that RFC 3161 universally mandates it for every valid end-entity certificate. Reject CA=true, missing, duplicate and malformed extensions.
3. Require exactly one parseable X.509 Key Usage extension containing at least one of digitalSignature or nonRepudiation (contentCommitment). Permit both together. Reject absent/duplicate/malformed usage and *every other bit*, including keyCertSign, cRLSign, keyEncipherment, dataEncipherment and keyAgreement. A Key Usage extension may be critical or noncritical; do not falsely assert that RFC 5280 requires a critical bit for every end-entity signer. Incompatible real QTSP certificates must fail closed pending an operator-reviewed policy and interoperability update, not be silently normalized.
4. Return a generic TimestampProviderResponseException with no original certificate bytes, implementation exception or provider-supplied values. All paths continue to store only **Unverified** evidence; none become qualified.
5. TDD: ADR first, actual disposable X.509 positive and negative tests RED, implementation GREEN, document operator gate and threat limitations, then demand exact final-main SHA 4/4 CI before closing #97. No API input, SQL privilege, on-prem/Azure divergence or registrar/WebAuthn stop-line change.

## Residual non-claims

This enforces only one leaf **certificate extension profile**, not cryptographically proven exclusive *private-key possession* or non-reuse. It does not establish legal historical EU Trusted List status, service type and time, real historical revocation evidence, CRL distribution/independently witnessed monotonic custody, UTC(k), HSM lifecycle, WORM preservation, CAB/AgID approval or an independently qualified TemporalMark TSA. Parents #15/#17/#13 remain OPEN.

## References

- [RFC 3161 §2.3](https://www.rfc-editor.org/rfc/rfc3161#section-2.3)
- [RFC 5280 §4.2.1.3 Key Usage](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3)
- [RFC 5280 §4.2.1.9 Basic Constraints](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9)
