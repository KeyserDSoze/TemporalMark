# ADR 0002 — No self-declared qualified time stamps

Status: Accepted (2026-11-15)

## Decision
Separate three states:
1. **DEVELOPMENT**: deterministic test doubles and non-qualified demo marks, only in explicitly marked development environments.
2. **DELEGATED**: integrate an independently verifiable external RFC 3161 QTSP, provided the external QTSP/service is qualified at the timestamp time. This does **not** make TemporalMark itself a QTSP. Retain provider identity, TSR, verification results and policy.
3. **OWN_QTSP**: enable issuance only after the legal entity and service have passed CAB assessment, relevant AgID procedure and Trusted List registration; enforce HSM, certificate, time accuracy, monitoring and stop-on-failure gates.

A REST request or tenant administrator cannot set `qualified=true`. Qualification evidence is not inferred from the cryptographic signature alone. Fail closed on ambiguous issuer status, key status, time health or evidence persistence. No fabricated signatures or silently issued local certificates may be represented as qualified.

## Why
eIDAS 910/2014 (amended), Articles 41–42; Commission Implementing Regulation (EU) 2025/1929; ETSI EN 319 421/422; RFC 3161; AgID qualification procedure.

## Sources
- https://eur-lex.europa.eu/eli/reg_impl/2025/1929/oj
- https://eur-lex.europa.eu/eli/reg/2014/910/2024-10-18/eng
- https://www.agid.gov.it/it/piattaforme/eidas/marche-temporali-verso-eidas
- https://www.rfc-editor.org/rfc/rfc3161
