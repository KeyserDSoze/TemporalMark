# ADR 0072 — Canonical bounded SHA-256 Base64 imprint at authenticated issue ingress

Status: Accepted for the **unqualified delegated pilot** (2026-11-18). Child [#103](https://github.com/KeyserDSoze/TemporalMark/issues/103) of open #15.

## Reviewed baseline

Reviewed ADR 0002 and 0071, `src/backend/business/TemporalMark.Business/Stamping/TimestampIssueService.cs`, existing Business tests, RFC3161 provider's binary 32-byte imprint check, `src/backend/applications/TemporalMark.Api/Program.cs`, README API contract, `docs/TSA_HTTP_TRANSPORT.md`, `docs/THREAT_MODEL.md` and `docs/ROADMAP.md`. The authenticated tenant-admin endpoint receives only an encoded SHA-256 digest, not a document. It currently calls `Convert.FromBase64String` on untrusted `digestBase64` **before checking its input length** and accepts any spelling decoded by .NET. Per [Microsoft .NET 10 documentation](https://learn.microsoft.com/en-us/dotnet/api/system.convert.frombase64string?view=net-10.0), decoding permits ignorable whitespace; [RFC 4648 §3.5](https://www.rfc-editor.org/rfc/rfc4648#section-3.5) warns nonzero unused pad bits can create aliases of the same octets. A 32-byte SHA-256 imprint has exactly 44 characters of canonical standard padded Base64, including one trailing `=`.

## Decision

1. Keep `digestBase64` as the existing JSON input and `ArgumentException` -> HTTP 400 contract. Before decoding, require **exactly 44 characters**. This avoids unnecessary allocation/decoder work for long attacker-controlled input and refuses whitespace variants. Then decode with `Convert.FromBase64String`, require exactly 32 bytes and exact ordinal identity with `Convert.ToBase64String(decoded)`. This also rejects pad-bit aliases, whitespace-only variants, URL-safe alphabet and alternate padding. Do not reflect the raw input in error messages or logs. Canonical matching is a **TemporalMark API policy**, not an assertion that RFC3161 defines JSON Base64 text.
2. Implement **RED-first** Business tests on a genuine 32-byte SHA-256 hash, reject overlong and alias/malformed inputs **before calling `ITimestampProvider` or `ITimestampWriter`**, and retain valid persistence as `Unverified`. Use the same service code on Azure and on-prem; no tenant override, provider configuration or database migration.
3. This is **not** request idempotency, billing reconciliation, a nonce/transaction replay store, rate limiting, a guarantee of exactly-once upstream TSA issuance, or evidence of QTSP qualification. A client may intentionally request multiple stamps over the same hash. Those concerns remain under #15/#17; legal CAB/AgID status remains #13.
4. Update API documentation, TSA operator guidance, threat model and roadmap. Close #103 only after independently verifying the **exact final docs-inclusive main SHA** `temporalmark/ci-4-core-jobs=success`, the linked successful four core jobs and actual test counts. Do not infer GREEN from a prior SHA.

## References

- [Microsoft Convert.FromBase64String](https://learn.microsoft.com/en-us/dotnet/api/system.convert.frombase64string?view=net-10.0)
- [RFC 4648 §3.5 canonical encoding](https://www.rfc-editor.org/rfc/rfc4648#section-3.5)
- [ADR 0002](0002-qualified-vs-delegated-timestamping.md)
