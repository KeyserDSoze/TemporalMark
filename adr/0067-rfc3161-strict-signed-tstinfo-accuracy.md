# ADR 0067 — Strict RFC 3161 TSTInfo claimed accuracy gate (unqualified pilot only)

Status: Accepted for the unqualified delegated TSA **pilot** (2026-11-18), scoped [#98](https://github.com/KeyserDSoze/TemporalMark/issues/98) under open #15. This gate does not establish qualified time.

## Reviewed baseline

Consulted ADR 0002 and ADR 0058–0066, `ExternalRfc3161TimestampProvider.RequestAsync`, `ExternalRfc3161IssuanceTimePolicy`, certificate-chain/CRL policies and test fixtures; `docs/TSA_HTTP_TRANSPORT.md`, `docs/THREAT_MODEL.md`, `docs/ROADMAP.md`. Existing response parsing confirms nonce/imprint, verified signer, signer policy, anchored path and signed full issuer CRLs; the live-window guard checks that CMS-signed `genTime` is plausible relative to *our untrusted local clock*, but there is no check for the signed declaration of UTC accuracy.

[RFC 3161 §2.4.2](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2) defines `TSTInfo.accuracy` as OPTIONAL and explains that an omitted value may be obtained through the TSA's policy OID instead. [The .NET 10 `Rfc3161TimestampTokenInfo` interface](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamptokeninfo?view=net-10.0) exposes the parsed signed `AccuracyInMicroseconds` as nullable `long`. The RFC also defines accuracy as uncertainty around `genTime`, *not an independently authenticated UTC(k) traceability measurement*.

## Decision

1. The **restricted TemporalMark pilot** requires an explicitly encoded `TSTInfo.accuracy` on every otherwise verified token and accepts only a nonnegative claimed accuracy **<= 1,000,000 microseconds (one second)**. Zero, if explicitly encoded, is syntactically allowed but no statement of real zero uncertainty. A missing signed field, a value above one second, negative or an unrepresentably large decoded value is denied with a generic `TimestampProviderResponseException`.
2. The ceiling is a **fixed fail-closed interoperability filter** in the provider, not an eIDAS legal threshold or proof of UTC(k). It is the same for the on-prem/Azure deployments and cannot be selected by tenants or by a TSA HTTP response header. A future real QTSP that legitimately omits accuracy in accordance with an authenticated policy will be rejected until independently reviewed policy documentation, test cases and a new ADR justify a different acceptance rule. Do not quietly default the missing field to zero.
3. Run the check only on `token.TokenInfo.AccuracyInMicroseconds` from a successfully verified CMS token, after nonce/hash/signer/PKIX/issuer CRL/live genTime validation and before constructing a `ProviderTimestamp`. It is a statement **made by the TSA**, not measurement of its hardware, clock or network path. Preserve `Unverified` receipts and all existing #15/#17/#13 launch gates.
4. TDD: commit this ADR first on `main`, then RED-first xUnit positive/negative tests (including actual .NET encoded/decoded unsigned `TSTInfo` as a parser fixture, *not a valid CMS response*), implement minimal gate, update docs/issue, then verify exact documentation-inclusive main HEAD four-job CI before closing #98. No SQL/permissions, browser, registrar, WORM, qualification label, or new cloud dependency changes.

## Residual risks

A compromised TSA may lie about accuracy while signing a valid token. The local 120s request/response window is not an attested clock; the numeric field does not replace UTC(k) synchronization evidence, independently logged time-health events, CAB/AgID/eIDAS conformance, historical EU Trusted List service qualification, CRL source verification, revocation archival, independent monotonic custody or WORM storage. All parent issues remain OPEN.

## References

- [RFC 3161 §2.4.2 TSTInfo accuracy](https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2)
- [.NET 10 Rfc3161TimestampTokenInfo](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.rfc3161timestamptokeninfo?view=net-10.0)
- [ADR 0062 live genTime](0062-rfc3161-live-gen-time-and-issuance-time-x509-path.md) and [ADR 0066 signer profile](0066-rfc3161-tsa-signer-end-entity-key-usage.md)
