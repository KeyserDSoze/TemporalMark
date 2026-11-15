# ADR 0009 — Database-bound independent enrollment approval (pilot)

Status: Accepted for development/pilot (2026-11-15)

Related: ADR 0003, 0006–0008, issues #14, #23, #25, #27 and #29.

## Context
The existing standalone CLI validated two OIDC users and their active tokens but could create a new organization immediately. A compromised operator account or the isolated provisioning SQL credential could trigger enrollment without any documented independent authorization. The qualified Timestamp Service Provider (QTSP) requirements do not follow from adding a local software approval mechanism.

## Decision
1. Use a **request → approve → complete** protocol. The operator and initial administrator present two separate, short-lived, cryptographically validated JWT access tokens, both checked live against Keycloak RFC 7662. The request generates a random UUID that will be the eventual organization ID; it records exact organization name, issuer, operator and first-admin `sub`, SHA-256 token hashes, and five-minute expiry. **No active organization is created during request or approval.**
2. A third principal is authenticated independently with a signed, live OIDC `platform_approver` token and distinct `sub`, expected audience `temporalmark-approval`. The approver explicitly confirms request UUID, exact name and both stable subjects. The SQL routine checks these values against the original pending request and rejects changes. This actor uses a dedicated approve-only DB role, distinct from the operator's request/complete-only role and the API runtime role.
3. PostgreSQL `V006` introduces the pending table and separate `temporalmark_approver_group`, plus restricted SECURITY DEFINER routines. The original `bootstrap_verified_organization` direct path loses its grant to the normal provisioning group. Migration owner retains break-glass capabilities under controlled DBA supervision.
4. Complete reauthenticates and rechecks active status for both the operator and intended first tenant admin. PostgreSQL compares UUID, name, issuer and both subjects to the prior approved request, rejects missing/reused/expired approval, marks it **consumed only inside the transaction** creating the organization, first membership and provisioning audit. A unique FK links audit to approval. Token hashes are unique; only hashed proofs, subjects and timestamps are persisted—not JWTs.
5. IdP status is checked at every action; positive results are never cached by the application. Concurrent approval or completion attempts serialize on the pending row update. `V007` fixes an expiry-boundary precision issue found in integration tests by taking one `clock_timestamp()` sample per request. Historical migration files remain immutable.
6. The CLI takes explicit `request`, `approve`, `complete` commands; no new public API or browser signup endpoint is introduced. A new development-only Keycloak `platform_approver` test user and separate local SQL login allow CI to validate three distinct identities.

## Trust boundaries and open risks
- **Pilot independent-signoff gate, NOT production four-eyes/MFA certification.** An operator in possession of the approver's token file or SQL credential could submit the approval. The CLI cannot prove the human independently reviewed the request, and there is no step-up MFA/ACR/AMR enforcement, hardware-backed signing or organization-level segregation-of-duties policy. Issue #27 stays OPEN.
- The approver must independently confirm the legal organization, both subjects and expected issuer from an approved external source; repeating fields given by the requester is insufficient as a production approval record. No tamper-evident audit/WORM or digitally signed policy decision yet (#17).
- Token validity/roles reported via introspection may be an issuance-time snapshot. The service lacks direct current-directory role checks and cannot eliminate IdP→SQL race windows (#25/#28). The five-minute TTL is intentionally restrictive for the development pilot and not an approved business SLA.
- Database owners/superusers can call legacy bootstrap routines or disable triggers; split DBA identities, PIM, immutable privileged audit and independent external governance are production prerequisites. No network/API exposure for the privileged CLI is authorized.
- Keycloak password-grant fixtures, sample SQL passwords and local HTTP are **development only**. Production requires vault credentials, TLS, approved interactive authentication and verified identity mapping. No key-ceremony, QTSP certification, CAB/AgID assessment or EU Trusted List status follows from these changes.

## References
- PostgreSQL privileges: https://www.postgresql.org/docs/17/sql-grant.html
- PostgreSQL transaction behavior: https://www.postgresql.org/docs/17/transaction-iso.html
- RFC 7662 live token status: https://www.rfc-editor.org/rfc/rfc7662
