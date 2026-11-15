# WebAuthn reviewer RP/origin deployment policy (pilot, issue #40)

**Not operational WebAuthn approval.** TemporalMark has an unsigned, non-consumable reviewer challenge (V012, ADR 0016) and a `.NET 10` **validation-only** `ReviewerWebAuthnRelyingPartyPolicy` value object (ADR 0017). The latter is not connected to a browser, API, IdP login, CLI, or signed assertion verifier. **Do not treat passing a policy comparison as authorization, signed human consent or legal evidence.**

## Proposed future deployment inputs (NOT existing environment variables)

An approved implementation will need at least:
- **RP ID**: a security-reviewed, canonical lowercase ASCII fully qualified DNS hostname, e.g. `review.example.org`; no scheme or port; no wildcard, IP, localhost, single-label name or trailing dot.
- **Trusted origin**: one exact HTTPS scheme/host/optional explicit non-default port, e.g. `https://review.example.org` or `https://review.example.org:8443`; no path (even `/`), query, fragment, userinfo or wildcard. RP ID must equal the origin host in this intentionally strict first profile.
- **Independent configuration approval** by operations/security: check ownership of DNS zone and certificates, TLS termination and reverse proxies, browser reachability, identity protection for reviewer UI, origin change controls and planned credential re-enrollment if the RP changes.

**On-prem:** use a production HTTPS FQDN and trusted certificate even for internal networks; do not assume local private IP/localhost or an HTTP browser exception qualifies. **Azure:** explicitly approve the actual HTTPS origin used by reviewers (custom domain/front door or equivalent) and pin it; never select the RP ID from `Host` or `X-Forwarded-Host` headers. A deployment does not gain WebAuthn support just by setting a DNS name.

The class currently has **no default configuration and no runtime consumer**. These are future operator requirements, not instructions to set unsupported `WEBAUTHN_*` variables. There is no WebAuthn endpoint or enrolled credential store. The standalone `challenge` command never consumes the challenge or changes enrollment state.

## Security/integration checklist before any real WebAuthn operation

1. Run independently approved reviewer credential enrollment using a maintained verifier library; only authorized administrators can approve and bind a credential to a stable current IAM principal. Do not accept self-registration, caller-provided keys or arbitrary hardware claims.
2. Validate `clientDataJSON.type`, exact approved origin and challenge, authenticator data's `rpIdHash`, authenticator signature, approved credential ID/public key, **UV**, the relevant sign counter policy and fresh IdP role/account state. Treat malformed CBOR, replay, mismatched actions/scopes and missing UV as denial.
3. Atomically record one verified signed decision and challenge consumption while applying approved/rejected terminal state in PostgreSQL. Remove the older approver group's ability to directly invoke unsigned approval/rejection routines; keep separate registration, reviewer and verifier SQL privileges.
4. Use actual browser ceremony tests plus negative and mutation tests on exact CI head. A disposable virtual authenticator alone is NOT independent physical key custody or human review. Preserve non-secret audit and threat documentation. Obtain independent security and legal sign-off; WORM/QTSP remain different requirements.

## TDD evidence

- RED tests commit: `18712417d989d0b51774f9ebe8eaeb6c9bccdf4f`; source class intentionally absent at that commit.
- GREEN policy implementation: `fcbbe3940499db75097e4088aeb8dc93527f2f99`.
- Security profile tests: `tests/backend/TemporalMark.Business.Tests/ReviewerWebAuthnRelyingPartyPolicyTests.cs`.
- Full exact-head CI status: see issue #40; do not infer success from commits alone.

Primary normative source: [W3C Web Authentication Level 3, Recommendation 2026-08-25](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/). Keep #38, #35, #31, #27, #17 and #13 open.
