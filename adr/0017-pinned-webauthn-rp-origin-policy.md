# ADR 0017 — Strict server-pinned WebAuthn RP ID and HTTPS origin

Status: **accepted only for validation-policy foundation**, 2026-11-15.
Child #40 of #38; follows ADR 0009–0016 and unsigned V012 challenge issuance (#39).

## Problem

A signed WebAuthn assertion cannot be trusted solely because its payload claims a plausible browser origin or RP ID. The relying party must **preconfigure** the origin and RP identifier independently of request headers, CLI arguments, tokens and browser parameters. WebAuthn Level 3 permits a valid registrable-domain suffix relationship, but that more flexible rule depends on a vetted public-suffix/origin policy. Cross-domain matching, loopback HTTP exceptions and insecure implicit defaults are inappropriate for a production approval boundary.

## Decision in this narrow slice

1. Introduce the pure .NET 10 `ReviewerWebAuthnRelyingPartyPolicy` value object in the business layer, tested independently before implementation (RED `18712417`, GREEN `fcbbe394`). It requires an **explicit, canonical, lowercase ASCII HTTPS origin** with a non-loopback DNS host. It rejects a path, trailing slash, query, fragment, user information, wildcard, malformed host, raw IP address, localhost and scheme downgrade. A non-default HTTPS port can be explicitly pinned and is then compared exactly.
2. Constrain the pilot RP ID to be **identical to that origin's host**, with exact case-sensitive string comparison and no subdomain/suffix fallback. This is intentionally more restrictive than the general WebAuthn RP ID rules. No public-suffix implementation or CNAME-based trust delegation is implied.
3. `MatchesDeclaredScope` only compares already-extracted public strings to this independently supplied policy. It does **not** check that the values actually came from a cryptographically validated `clientDataJSON` and signed `authenticatorData`. It must **never** be used as an authorization predicate by itself.
4. This pilot class has **no current production runtime configuration or consumers**: there is no WebAuthn registration/assertion endpoint, server credential trust, authenticator signature, challenge consumption, decision authorization or SQL grant change. Future integration MUST enforce startup fail-closed when origin/RP is not pinned and MUST obtain the values from verified signed protocol objects, not caller-controlled request fields.
5. Unit tests cover configured-origin confusion, HTTPS port mismatch, domain lookalikes, suffix/prefix traps, username abuse, paths, wildcards, uppercase input, loopback/IP addresses and incorrect assertion declarations. They prove only the policy's fail-closed behavior; they do not validate WebAuthn signatures.

## Future security gate (#38 stays OPEN)

A production verifier requires approved independent key enrollment, a maintained audited WebAuthn/FIDO2 library, strict validation of authenticator data and client JSON, signature and credential binding, RP ID SHA-256 comparison, exact origin, user verification (UV), challenge/version/decision/scope match, replay resistance, signCount/counter policy, independent human confirmation, atomic one-time SQL consumption, and revocation of old direct SQL approve/reject EXECUTE. Attestation and physical independent possession are separate governance questions. A static RP origin policy is **not proof of WebAuthn consent** and does not turn TemporalMark into a QTSP or WORM system.

Production review must separately sign off approved DNS domains, HTTPS/TLS certificates, reverse-proxy host handling, port/origin configuration for on-prem and Azure, incident handling, RP rotation and credential portability. A public URL must not become trusted merely because a client can reach it. See `docs/WEBAUTHN_RP_POLICY.md` and the threat model.

## References

- W3C Recommendation, Web Authentication Level 3 (25 August 2026): https://www.w3.org/TR/2026/REC-webauthn-3-20260825/
- Previous unsigned challenge boundary: `adr/0016-server-issued-reviewer-challenge.md`
- Remaining independently verified human approval: #38/#35/#31/#27; evidence and qualification #17/#13.
