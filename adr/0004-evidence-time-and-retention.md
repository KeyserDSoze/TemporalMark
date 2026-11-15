# ADR 0004 — Evidence preservation, time and retention

Status: Accepted (2026-11-15)

- Accept document message imprints (digest), not document bytes, wherever possible.
- Preserve the raw RFC 3161 DER timestamp response, the digest, OID/policy, serial, issuing TSU, cert fingerprint, source and time-health measurements, immutable log reference and verification result.
- Store evidence in immutable/WORM storage with tested legal hold, authorization, backup, DR and independent integrity verification. PostgreSQL is an indexed registry, not by itself a WORM record.
- A production TSU must use dedicated, purpose-only cryptographic keys in independently assessed HSM hardware. Calibrated UTC(k) sources, dual-source monitoring, traceability proof, drift thresholds and automatic stop-on-desynchronization are required.
- The user's initial business policy is indefinite retention. This must be revisited against GDPR storage limitation, data minimization, contractual duties, incident handling, exceptional deletion requirements, key/certificate expiration and long-term validation. `Forever` is a policy objective, not a technical or legal guarantee.
- Period exports contain manifest, metadata, evidence identifiers and raw timestamp tokens; receipts must be verifiable offline. Asynchronous large exports need audit logs, quotas and expiry controls.

Local Docker volumes are explicitly **not** a substitute for legal WORM/UTC/HSM evidence. Azure immutable storage settings alone do not demonstrate compliance; on-premise object-lock capabilities require independent assessment.
