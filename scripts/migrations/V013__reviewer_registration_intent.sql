-- V013: owner-pinned RP policy and registrar-only UNCONSUMABLE registration INTENT.
-- Not a verified WebAuthn registration, credential, attestation, approval or signature.
-- No role login, group membership, default policy, trusted public key or API is seeded.
-- V001-V012 are immutable and their checksums must remain unchanged.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles
                   WHERE rolname='temporalmark_credential_registrar_group') THEN
        CREATE ROLE temporalmark_credential_registrar_group NOLOGIN;
    END IF;
END;
$$;
GRANT USAGE ON SCHEMA public TO temporalmark_credential_registrar_group;

-- Only a controlled migration owner can pin an HTTPS RP policy. In this first
-- profile the origin is EXACTLY https://<lowercase RP DNS>, default TLS port.
-- No localhost, wildcard, caller-selected RP, dynamic origin or seed default.
CREATE TABLE public.reviewer_registration_rp_policies (
    identity_issuer text NOT NULL
        CHECK (char_length(identity_issuer) BETWEEN 10 AND 1024
               AND identity_issuer=btrim(identity_issuer)
               AND identity_issuer LIKE 'https://%'
               AND identity_issuer !~ '[[:cntrl:][:space:]]'),
    rp_id text NOT NULL
        CHECK (char_length(rp_id) BETWEEN 4 AND 253
               AND rp_id ~ '^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)+$'),
    trusted_origin text NOT NULL,
    change_reference text NOT NULL
        CHECK (char_length(change_reference) BETWEEN 8 AND 128
               AND change_reference=btrim(change_reference)
               AND change_reference !~ '[[:cntrl:]]'),
    pinned_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(identity_issuer, rp_id),
    CONSTRAINT ck_registration_policy_exact_https_origin
        CHECK (trusted_origin='https://' || rp_id)
);
REVOKE ALL ON public.reviewer_registration_rp_policies FROM PUBLIC;
REVOKE ALL ON public.reviewer_registration_rp_policies FROM
    temporalmark_credential_registrar_group, temporalmark_approver_group,
    temporalmark_provisioner_group, temporalmark_runtime_group;
COMMENT ON TABLE public.reviewer_registration_rp_policies IS
'Owner-pinned first-profile issuer/HTTPS RP policy. No default policy, credential or authorization; schema owner can still alter this ordinary SQL table.';

-- One registrar-authorized challenge EVER per reviewer/issuer/RP until a
-- new audited recovery/rotation protocol is designed. No key is activated.
CREATE TABLE public.reviewer_registration_intents (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    identity_issuer text NOT NULL,
    rp_id text NOT NULL,
    trusted_origin text NOT NULL,
    reviewer_subject text NOT NULL
        CHECK (char_length(reviewer_subject) BETWEEN 1 AND 255
               AND reviewer_subject=btrim(reviewer_subject)
               AND reviewer_subject !~ '[[:cntrl:]]'),
    registrar_subject text NOT NULL
        CHECK (char_length(registrar_subject) BETWEEN 1 AND 255
               AND registrar_subject=btrim(registrar_subject)
               AND registrar_subject !~ '[[:cntrl:]]'),
    nonce bytea NOT NULL UNIQUE CHECK (octet_length(nonce)=48),
    issued_utc timestamptz NOT NULL,
    expires_utc timestamptz NOT NULL,
    protocol_version smallint NOT NULL DEFAULT 1 CHECK (protocol_version=1),
    FOREIGN KEY (identity_issuer, rp_id)
        REFERENCES public.reviewer_registration_rp_policies(identity_issuer, rp_id),
    UNIQUE (identity_issuer, reviewer_subject, rp_id),
    CONSTRAINT ck_registration_distinct_registrar
        CHECK (reviewer_subject<>registrar_subject),
    CONSTRAINT ck_registration_pinned_origin
        CHECK (trusted_origin='https://' || rp_id),
    CONSTRAINT ck_registration_short_ttl
        CHECK (expires_utc>issued_utc
               AND expires_utc<=issued_utc+interval '2 minutes')
);
REVOKE ALL ON public.reviewer_registration_intents FROM PUBLIC;
REVOKE ALL ON public.reviewer_registration_intents FROM
    temporalmark_credential_registrar_group, temporalmark_approver_group,
    temporalmark_provisioner_group, temporalmark_runtime_group;
COMMENT ON TABLE public.reviewer_registration_intents IS
'Unconsumable short-lived intent ONLY. Contains no credential/public key/attestation, no approval and no signed signer proof. Ordinary PostgreSQL, not legal WORM.';

-- A restricted role cannot change historical scopes or reissue a nonce.
-- This is an ordinary trigger, never evidence of legal immutability: schema
-- owners and superusers can remove triggers and modify tables.
CREATE FUNCTION public.block_reviewer_registration_mutation()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'Pinned RP policies and registration intents cannot be updated or deleted'
        USING ERRCODE='23514';
END;
$$;
REVOKE ALL ON FUNCTION public.block_reviewer_registration_mutation() FROM PUBLIC;

CREATE TRIGGER trg_registration_policies_append_only
BEFORE UPDATE OR DELETE ON public.reviewer_registration_rp_policies
FOR EACH ROW EXECUTE FUNCTION public.block_reviewer_registration_mutation();
CREATE TRIGGER trg_registration_intents_append_only
BEFORE UPDATE OR DELETE ON public.reviewer_registration_intents
FOR EACH ROW EXECUTE FUNCTION public.block_reviewer_registration_mutation();

-- Current role/issuer/subject values are ONLY caller-provided text.
-- The NOLOGIN role has no seeded members. No untrusted HTTP/CLI can issue.
-- A future independently authenticated registrar service must reverify signed,
-- live, fresh IdP authorization outside this routine before any invocation.
CREATE FUNCTION public.issue_reviewer_registration_intent(
    expected_issuer text, reviewer_sub text, registrar_sub text,
    expected_rp text, expected_origin text)
RETURNS TABLE (
    intent_id uuid, challenge_hex text,
    issued_utc timestamptz, expires_utc timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    approved_origin text;
    fresh_nonce bytea;
    issued_at timestamptz;
BEGIN
    IF expected_issuer IS NULL OR
       char_length(expected_issuer) NOT BETWEEN 10 AND 1024 OR
       expected_issuer<>btrim(expected_issuer) OR
       expected_issuer NOT LIKE 'https://%' OR
       expected_issuer ~ '[[:cntrl:][:space:]]' OR
       expected_rp IS NULL OR expected_origin IS NULL OR
       reviewer_sub IS NULL OR char_length(reviewer_sub) NOT BETWEEN 1 AND 255 OR
       reviewer_sub<>btrim(reviewer_sub) OR reviewer_sub ~ '[[:cntrl:]]' OR
       registrar_sub IS NULL OR char_length(registrar_sub) NOT BETWEEN 1 AND 255 OR
       registrar_sub<>btrim(registrar_sub) OR registrar_sub ~ '[[:cntrl:]]' OR
       reviewer_sub=registrar_sub
    THEN
        RAISE EXCEPTION 'Invalid independent registrar intent scope'
            USING ERRCODE='22023';
    END IF;

    SELECT p.trusted_origin INTO approved_origin
    FROM public.reviewer_registration_rp_policies AS p
    WHERE p.identity_issuer=expected_issuer
      AND p.rp_id=expected_rp
      AND p.trusted_origin=expected_origin;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'No owner-approved RP policy for this issuer and origin'
            USING ERRCODE='23514';
    END IF;

    -- 3 independent PostgreSQL v4 UUID values: 48 bytes, ~366 random bits
    -- after the fixed UUID version/variant bits. No caller-provided nonce.
    fresh_nonce := decode(
           replace(gen_random_uuid()::text,'-','')
        || replace(gen_random_uuid()::text,'-','')
        || replace(gen_random_uuid()::text,'-',''),'hex');
    issued_at := clock_timestamp();

    INSERT INTO public.reviewer_registration_intents AS r
        (id,identity_issuer,rp_id,trusted_origin,reviewer_subject,
         registrar_subject,nonce,issued_utc,expires_utc)
    VALUES
        (gen_random_uuid(),expected_issuer,expected_rp,approved_origin,
         reviewer_sub,registrar_sub,fresh_nonce,
         issued_at,issued_at+interval '2 minutes')
    RETURNING r.id,upper(encode(r.nonce,'hex')),r.issued_utc,r.expires_utc
    INTO intent_id,challenge_hex,issued_utc,expires_utc;
    RETURN NEXT;
END;
$$;
REVOKE ALL ON FUNCTION public.issue_reviewer_registration_intent(
    text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.issue_reviewer_registration_intent(
    text,text,text,text,text) TO temporalmark_credential_registrar_group;
COMMENT ON FUNCTION public.issue_reviewer_registration_intent(
    text,text,text,text,text) IS
'Owner-pinned unconsumable enrollment intent ONLY; signed/current independent registrar proof and WebAuthn credential creation/verification NOT implemented.';
