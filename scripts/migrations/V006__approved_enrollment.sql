-- V006: independent approval boundary for new tenant enrollment.
-- No migration rewrite, no public REST registration, no privilege escalation to API.
DO $$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='temporalmark_approver_group') THEN
        CREATE ROLE temporalmark_approver_group NOLOGIN;
    END IF;
END $$;
GRANT USAGE ON SCHEMA public TO temporalmark_approver_group;

CREATE TABLE public.organization_enrollment_requests (
    id uuid PRIMARY KEY CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    organization_name text NOT NULL
        CHECK (char_length(organization_name) BETWEEN 1 AND 200 AND organization_name=btrim(organization_name)
               AND organization_name !~ '[[:cntrl:]]'),
    identity_issuer text NOT NULL
        CHECK (char_length(identity_issuer) BETWEEN 10 AND 1024 AND identity_issuer ~ '^https?://'
               AND identity_issuer !~ '[[:cntrl:]]'),
    operator_subject text NOT NULL
        CHECK (char_length(operator_subject) BETWEEN 1 AND 255 AND operator_subject=btrim(operator_subject)
               AND operator_subject !~ '[[:cntrl:]]'),
    first_admin_subject text NOT NULL
        CHECK (char_length(first_admin_subject) BETWEEN 1 AND 255 AND first_admin_subject=btrim(first_admin_subject)
               AND first_admin_subject !~ '[[:cntrl:]]'),
    operator_request_sha256 char(64) NOT NULL UNIQUE
        CHECK (operator_request_sha256 ~ '^[0-9A-F]{64}$'),
    admin_request_sha256 char(64) NOT NULL UNIQUE
        CHECK (admin_request_sha256 ~ '^[0-9A-F]{64}$'),
    requested_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_utc timestamptz NOT NULL,
    approved_by_subject text
        CHECK (approved_by_subject IS NULL OR
            (char_length(approved_by_subject) BETWEEN 1 AND 255
             AND approved_by_subject=btrim(approved_by_subject)
             AND approved_by_subject !~ '[[:cntrl:]]')),
    approval_proof_sha256 char(64) UNIQUE
        CHECK (approval_proof_sha256 IS NULL OR approval_proof_sha256 ~ '^[0-9A-F]{64}$'),
    approved_utc timestamptz,
    consumed_utc timestamptz,
    CHECK (operator_subject <> first_admin_subject),
    CHECK (approved_by_subject IS NULL OR
           (approved_by_subject <> operator_subject AND approved_by_subject <> first_admin_subject)),
    CHECK ((approved_by_subject IS NULL AND approval_proof_sha256 IS NULL AND approved_utc IS NULL) OR
           (approved_by_subject IS NOT NULL AND approval_proof_sha256 IS NOT NULL AND approved_utc IS NOT NULL)),
    CHECK (consumed_utc IS NULL OR approved_utc IS NOT NULL),
    CHECK (expires_utc > requested_utc AND expires_utc <= requested_utc + interval '5 minutes')
);

ALTER TABLE public.organization_provisioning_events
    ADD COLUMN approval_request_id uuid UNIQUE REFERENCES public.organization_enrollment_requests(id),
    ADD COLUMN approver_subject text;

-- V004 direct SQL function is now unavailable to both runtime and enrollment roles.
-- The migration owner retains access for controlled legacy break-glass only.
REVOKE ALL ON FUNCTION public.bootstrap_verified_organization(
    uuid,text,text,text,text,char(64),char(64)) FROM temporalmark_provisioner_group;
REVOKE ALL ON FUNCTION public.bootstrap_verified_organization(
    uuid,text,text,text,text,char(64),char(64)) FROM PUBLIC;

CREATE FUNCTION public.request_enrollment(
    request_id uuid, requested_name text, expected_issuer text, operator_sub text,
    admin_sub text, request_operator_hash char(64), request_admin_hash char(64))
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO public.organization_enrollment_requests
        (id,organization_name,identity_issuer,operator_subject,first_admin_subject,
         operator_request_sha256,admin_request_sha256,expires_utc)
    VALUES
        (request_id,requested_name,expected_issuer,operator_sub,admin_sub,
         request_operator_hash,request_admin_hash,clock_timestamp()+interval '5 minutes');
    RETURN request_id;
END;
$$;
REVOKE ALL ON FUNCTION public.request_enrollment(
    uuid,text,text,text,text,char(64),char(64)) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_enrollment(
    uuid,text,text,text,text,char(64),char(64)) TO temporalmark_provisioner_group;

CREATE FUNCTION public.approve_enrollment(
    request_id uuid, expected_name text, expected_issuer text, expected_operator_sub text,
    expected_admin_sub text, approver_sub text, approver_hash char(64))
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    approved_id uuid;
BEGIN
    IF approver_sub IS NULL OR char_length(approver_sub) NOT BETWEEN 1 AND 255
       OR approver_sub <> btrim(approver_sub) OR approver_sub ~ '[[:cntrl:]]'
       OR approver_hash IS NULL OR approver_hash !~ '^[0-9A-F]{64}$'
    THEN
        RAISE EXCEPTION 'Invalid approval data' USING ERRCODE='22023';
    END IF;
    UPDATE public.organization_enrollment_requests r
       SET approved_by_subject=approver_sub, approval_proof_sha256=approver_hash,
           approved_utc=clock_timestamp()
     WHERE r.id=request_id AND r.organization_name=expected_name
       AND r.identity_issuer=expected_issuer AND r.operator_subject=expected_operator_sub
       AND r.first_admin_subject=expected_admin_sub
       AND r.operator_subject<>approver_sub AND r.first_admin_subject<>approver_sub
       AND r.approved_utc IS NULL AND r.consumed_utc IS NULL
       AND r.expires_utc>clock_timestamp()
     RETURNING r.id INTO approved_id;
    IF approved_id IS NULL THEN
        RAISE EXCEPTION 'Approval request missing, mismatched, expired or already approved'
            USING ERRCODE='23514';
    END IF;
    RETURN approved_id;
END;
$$;
REVOKE ALL ON FUNCTION public.approve_enrollment(
    uuid,text,text,text,text,text,char(64)) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.approve_enrollment(
    uuid,text,text,text,text,text,char(64)) TO temporalmark_approver_group;

CREATE FUNCTION public.complete_enrollment(
    request_id uuid, confirmed_name text, confirmed_issuer text,
    confirmed_operator_sub text, confirmed_admin_sub text,
    operator_hash char(64), admin_hash char(64))
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    approved_by text;
BEGIN
    IF operator_hash IS NULL OR operator_hash !~ '^[0-9A-F]{64}$'
        OR admin_hash IS NULL OR admin_hash !~ '^[0-9A-F]{64}$'
    THEN
        RAISE EXCEPTION 'Invalid signed proof hashes' USING ERRCODE='22023';
    END IF;
    -- Atomic row lock/consumption; competing completed transactions observe consumed_utc.
    UPDATE public.organization_enrollment_requests r
       SET consumed_utc=clock_timestamp()
     WHERE r.id=request_id
       AND r.organization_name=confirmed_name AND r.identity_issuer=confirmed_issuer
       AND r.operator_subject=confirmed_operator_sub AND r.first_admin_subject=confirmed_admin_sub
       AND r.approved_by_subject IS NOT NULL AND r.approval_proof_sha256 IS NOT NULL
       AND r.approved_utc IS NOT NULL AND r.consumed_utc IS NULL
       AND r.expires_utc>clock_timestamp()
     RETURNING r.approved_by_subject INTO approved_by;
    IF approved_by IS NULL THEN
        RAISE EXCEPTION 'Enrollment not approved, mismatched, expired or already consumed'
            USING ERRCODE='23514';
    END IF;

    PERFORM public.bootstrap_organization(request_id,confirmed_name,confirmed_admin_sub);
    INSERT INTO public.organization_provisioning_events
       (id,organization_id,first_admin_subject,identity_issuer,provisioner_subject,
        operator_proof_sha256,admin_proof_sha256,approval_request_id,approver_subject)
    VALUES
       (gen_random_uuid(),request_id,confirmed_admin_sub,confirmed_issuer,confirmed_operator_sub,
        operator_hash,admin_hash,request_id,approved_by);
    RETURN request_id;
END;
$$;
REVOKE ALL ON FUNCTION public.complete_enrollment(
    uuid,text,text,text,text,char(64),char(64)) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.complete_enrollment(
    uuid,text,text,text,text,char(64),char(64)) TO temporalmark_provisioner_group;
COMMENT ON TABLE public.organization_enrollment_requests IS
'Pilot approval records only. Database-owner can bypass; not qualified/WORM.';
