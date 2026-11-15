-- V012: unconsumable WebAuthn decision challenge foundation. NO SIGNATURE VERIFICATION
-- and NO approval/rejection path from a challenge alone. Historical migrations remain unchanged.
-- PostgreSQL 17 gen_random_uuid() derives from the strong random generator. Three
-- v4 UUIDs contain ~366 random bits even after version/variant bits are fixed,
-- exceeding the WebAuthn recommended >=128-bit entropy. No pgcrypto dependency.
CREATE TABLE public.organization_decision_challenges (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    request_id uuid NOT NULL UNIQUE REFERENCES public.organization_enrollment_requests(id),
    identity_issuer text NOT NULL
        CHECK (char_length(identity_issuer) BETWEEN 10 AND 1024),
    reviewer_subject text NOT NULL
        CHECK (char_length(reviewer_subject) BETWEEN 1 AND 255
               AND reviewer_subject=btrim(reviewer_subject)
               AND reviewer_subject !~ '[[:cntrl:]]'),
    original_review_sha256 char(64) NOT NULL
        CHECK (original_review_sha256 ~ '^[0-9A-F]{64}$'),
    decision text NOT NULL CHECK (decision IN ('APPROVE','REJECT')),
    reason_code text,
    nonce bytea NOT NULL UNIQUE CHECK (octet_length(nonce)=48),
    issued_utc timestamptz NOT NULL,
    expires_utc timestamptz NOT NULL,
    protocol_version smallint NOT NULL DEFAULT 1 CHECK (protocol_version=1),
    CONSTRAINT ck_decision_challenge_reason CHECK (
        (decision='APPROVE' AND reason_code IS NULL)
        OR (decision='REJECT' AND reason_code IS NOT NULL
            AND reason_code IN
                ('UNVERIFIED_ORGANIZATION','UNVERIFIED_IDENTITY',
                 'SCOPE_MISMATCH','POLICY_DENIED'))
    ),
    CONSTRAINT ck_decision_challenge_ttl CHECK (
        expires_utc>issued_utc AND expires_utc<=issued_utc+interval '60 seconds')
);
REVOKE ALL ON TABLE public.organization_decision_challenges FROM PUBLIC;
REVOKE ALL ON TABLE public.organization_decision_challenges FROM
    temporalmark_approver_group, temporalmark_provisioner_group, temporalmark_runtime_group;
COMMENT ON TABLE public.organization_decision_challenges IS
'Pilot server-generated pending decision challenges ONLY; NOT signed authorizations, WebAuthn assertions, or legal WORM evidence. No consumer exists.';

-- This helper independently calculates the byte-for-byte domain-separated
-- SHA-256 contract of PendingOrganizationReview.ReviewSha256 in .NET.
-- UTF-8 length prefixes use pg_catalog.int4send (big endian).
-- PostgreSQL stores timestamptz to microseconds: .NET UTC ticks = epoch*1e7
-- + 621355968000000000 (10,000,000 ticks/sec from year 0001).
CREATE FUNCTION public.canonical_enrollment_review_sha256(
    original_id uuid, original_name text, original_issuer text,
    original_operator text, original_admin text, original_expiry timestamptz)
RETURNS char(64) LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    canonical bytea := convert_to('TemporalMark.PendingReview.v1','UTF8')
                         || decode('00','hex');
    segment text;
    encoded bytea;
    expiry_ticks bigint :=
        (extract(epoch FROM original_expiry)*10000000)::bigint
        + 621355968000000000;
BEGIN
    FOREACH segment IN ARRAY ARRAY[
        original_id::text, original_name, original_issuer,
        original_operator, original_admin, expiry_ticks::text]
    LOOP
        encoded := convert_to(segment,'UTF8');
        canonical := canonical || int4send(octet_length(encoded)) || encoded;
    END LOOP;
    RETURN upper(encode(sha256(canonical),'hex'))::char(64);
END;
$$;
REVOKE ALL ON FUNCTION public.canonical_enrollment_review_sha256(
    uuid,text,text,text,text,timestamptz) FROM PUBLIC;

-- An append-only row: the signable challenge is never reissued/replaced.
-- Future signature verification must introduce a NEW, independently reviewed
-- atomic consumption path and separate signing-credential enrollment policy.
CREATE FUNCTION public.block_decision_challenge_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'Issued decision challenges cannot be altered or deleted'
        USING ERRCODE='23514';
END;
$$;
REVOKE ALL ON FUNCTION public.block_decision_challenge_mutation() FROM PUBLIC;
CREATE TRIGGER trg_decision_challenge_append_only
BEFORE UPDATE OR DELETE ON public.organization_decision_challenges
FOR EACH ROW EXECUTE FUNCTION public.block_decision_challenge_mutation();

CREATE FUNCTION public.issue_reviewer_decision_challenge(
    requested_id uuid, expected_name text, expected_issuer text,
    expected_operator_sub text, expected_admin_sub text,
    reviewer_sub text, review_hash char(64), intended_decision text, intended_reason text)
RETURNS TABLE (
    challenge_id uuid, challenge_hex text, issued_utc timestamptz, expires_utc timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    pending_expiry timestamptz;
    pending_now timestamptz;
    full_nonce bytea;
BEGIN
    IF requested_id IS NULL OR
       requested_id='00000000-0000-0000-0000-000000000000'::uuid
       OR reviewer_sub IS NULL OR char_length(reviewer_sub) NOT BETWEEN 1 AND 255
       OR reviewer_sub<>btrim(reviewer_sub) OR reviewer_sub ~ '[[:cntrl:]]'
       OR review_hash IS NULL OR review_hash !~ '^[0-9A-F]{64}$'
       OR NOT (
           (intended_decision='APPROVE' AND intended_reason IS NULL)
           OR (intended_decision='REJECT' AND intended_reason IS NOT NULL
               AND intended_reason IN
                  ('UNVERIFIED_ORGANIZATION','UNVERIFIED_IDENTITY',
                   'SCOPE_MISMATCH','POLICY_DENIED')))
    THEN
        RAISE EXCEPTION 'Invalid decision challenge scope' USING ERRCODE='22023';
    END IF;

    -- Lock ORIGINAL pending request, never trusting operator-supplied metadata.
    -- A concurrent terminal approval/rejection changes the same locked row.
    SELECT r.expires_utc INTO pending_expiry
    FROM public.organization_enrollment_requests AS r
    WHERE r.id=requested_id
      AND r.organization_name=expected_name
      AND r.identity_issuer=expected_issuer
      AND r.operator_subject=expected_operator_sub
      AND r.first_admin_subject=expected_admin_sub
      AND reviewer_sub<>r.operator_subject AND reviewer_sub<>r.first_admin_subject
      AND r.approved_utc IS NULL AND r.rejected_utc IS NULL
      AND r.consumed_utc IS NULL AND r.expires_utc>clock_timestamp()
      AND review_hash=public.canonical_enrollment_review_sha256(
        r.id,r.organization_name,r.identity_issuer,r.operator_subject,
        r.first_admin_subject,r.expires_utc)
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Original pending review invalid or unavailable'
            USING ERRCODE='23514';
    END IF;
    pending_now := clock_timestamp();
    IF pending_expiry<=pending_now THEN
        RAISE EXCEPTION 'Pending request has expired' USING ERRCODE='23514';
    END IF;

    -- 3 independently generated v4 UUIDs = 48 bytes / at least 366 random bits.
    -- Version/variant bits are fixed; never call this a uniformly random 384-bit key.
    full_nonce := decode(
         replace(gen_random_uuid()::text,'-','')
      || replace(gen_random_uuid()::text,'-','')
      || replace(gen_random_uuid()::text,'-',''),'hex');

    INSERT INTO public.organization_decision_challenges AS c
        (id,request_id,identity_issuer,reviewer_subject,original_review_sha256,
         decision,reason_code,nonce,issued_utc,expires_utc)
    VALUES
        (gen_random_uuid(),requested_id,expected_issuer,reviewer_sub,review_hash,
         intended_decision,intended_reason,full_nonce,pending_now,
         least(pending_now+interval '60 seconds',pending_expiry))
    RETURNING c.id,upper(encode(c.nonce,'hex')),
              c.issued_utc,c.expires_utc
         INTO challenge_id,challenge_hex,issued_utc,expires_utc;
    RETURN NEXT;
END;
$$;
REVOKE ALL ON FUNCTION public.issue_reviewer_decision_challenge(
    uuid,text,text,text,text,text,char(64),text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.issue_reviewer_decision_challenge(
    uuid,text,text,text,text,text,char(64),text,text)
    TO temporalmark_approver_group;
COMMENT ON FUNCTION public.issue_reviewer_decision_challenge(
    uuid,text,text,text,text,text,char(64),text,text) IS
'Issue one bound random challenge for a pending original reviewer scope; no user signature is checked; does NOT authorize approve/reject. Only reviewer SQL group may issue.';
