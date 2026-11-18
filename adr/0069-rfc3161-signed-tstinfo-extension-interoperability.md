# ADR 0069 — Strict no-extensions TSTInfo pilot acceptance policy

Status: Accepted for the **unqualified delegated RFC3161 pilot**, 2026-11-18. Scope [#100](https://github.com/KeyserDSoze/TemporalMark/issues/100), child of open #15.

## Reviewed baseline and interoperability

Reviewed ADR 0002, ADR 0058–0068, `ExternalRfc3161TimestampProvider.RequestAsync`, `ExternalRfc3161SignedAccuracyPolicy`, the other signer/policy/time/CRL gates, TSTInfo unit tests, `docs/TSA_HTTP_TRANSPORT.md`, `docs/THREAT_MODEL.md` and `docs/ROADMAP.md`. RFC3161 §2.4.2 defines `TSTInfo.extensions [1] IMPLICIT Extensions OPTIONAL`. These are not the X.509 *certificate* BasicConstraints, Key Usage or EKU extensions. .NET 10 exposes the decoded TSTInfo `Rfc3161TimestampTokenInfo.HasExtensions` and `GetExtensions()` but does not interpret the semantics of every unknown OID. The delegated provider currently verifies CMS signature/imprint/nonce, pinned signer, signed policy and genTime, strict claimed accuracy and custom-root issuer CRLs, **without examining TSTInfo extensions**.

RFC3161 §2.4.1 explicitly requires **the TSA** to reject unknown request extensions, critical or not; that paragraph **does not itself impose an identical unconditional rule on a client receiving all TSTInfo response extensions**. This is therefore an intentionally **narrower TemporalMark pilot interoperability choice**, not an alleged universal eIDAS or RFC3161 requirement. Some genuine QTSP responses may include extensions; such providers must be rejected by this pilot until approved semantic interpretation is added by a separate ADR and test suite.

## Decision

1. Only after the actual CMS signer and all existing RFC3161 verification gates succeed, require that the **CMS-signed** `Rfc3161TimestampTokenInfo` has **no TSTInfo extensions**. Reject presence of *any* extension OID, critical or noncritical, without attempting to interpret or log the OID/bytes. The absence of the extension set is accepted; the usual token status stays `Unverified`. A null token-info input fails closed in the isolated policy.
2. Use an isolated `ExternalRfc3161TstInfoExtensionPolicy.ValidateVerifiedTokenInfo` that throws a generic `TimestampProviderResponseException`; invoke it after strict signed-accuracy validation and before any `ProviderTimestamp` is constructed. Do not trust a mere self-encoded TSTInfo: caller must have independently verified cryptographic CMS signature, nonce, imprint, pin, policy, genTime, PKIX and signed issuer CRLs. The policy helper alone is not a verifier.
3. RED-first xUnit tests generate real .NET 10 ASN.1 DER TSTInfo via `Rfc3161TimestampTokenInfo.Encode/TryDecode` with no extensions, one unknown critical, one unknown noncritical and multiple criticality-mixed extensions. The fixture is **unsigned and intentionally not a QTSP timestamp**. GREEN minimal helper and provider call. Update TSA operator runbook, threat model and roadmap, then demand exact final documentation-inclusive `main` HEAD backend/frontend/terraform/docker-smoke 4/4 CI before closing #100.
4. No tenant-controlled extension allowlist, no bypass, no new API/database setting, no change to on-prem/Azure parity, no WebAuthn/SQL registrar activation, and no qualified-trust claim.

## Limits

This does not solve historical EU Trusted List service qualification, UTC(k), genuinely witnessed CRL provenance, external issuance reconciliation, retention/WORM, CAB/AgID/eIDAS approval or registered TSA status. An otherwise valid qualified provider may produce a response rejected by this intentionally restricted pilot. Parent #15/#17/#13 and unverified preceding #97/#98/#99 stay OPEN, and evidence state remains `Unverified`.

## References

- [RFC3161 §2.4.1 and §2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2)
- [.NET 10 Rfc3161TimestampTokenInfo](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamptokeninfo?view=net-10.0)
- [ADR 0067 signed accuracy gate](0067-rfc3161-strict-signed-tstinfo-accuracy.md)
