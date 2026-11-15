-- V008: auditable assurance provenance with exact role-bound SQL approval signature.
-- Historical migration files are immutable. Existing approved rows are labelled
-- LEGACY_UNVERIFIED (never retroactively claimed to have verified MFA).
ALTER TABLE public.organization_enrollment_requests
    ADD COLUMN approver_assurance_kind text,
    ADD COLUMN approver_authentication_acr text,
    ADD COLUMN approver_authentication_utc timestamptz,
    ADD COLUMN approval_policy_id text;

UPDATE public.organization_enrollment_requests
   SET approver_assurance_kind='LEGACY_UNVERIFIED',
       approval_policy_id='legacy-pre-v008'
 WHERE approved_utc IS NOT NULL;

ALTER TABLE public.organization_enrollment_requests
  ADD CONSTRAINT ck_approval_assurance_provenance CHECK (
    (approved_utc IS NULL AND approver_assurance_kind IS NULL
     AND approver_authentication_acr IS NULL
     AND approver_authentication_utc IS NULL AND approval_policy_id IS NULL)
    OR
    (approved_utc IS NOT NULL AND (
        (approver_assurance_kind='LEGACY_UNVERIFIED'
         AND approval_policy_id='legacy-pre-v008'
         AND approver_authentication_acr IS NULL
         AND approver_authentication_utc IS NULL)
       OR
        (approver_assurance_kind='DISPOSABLE_PASSWORD_ONLY'
         AND approval_policy_id='disposable-keycloak-pilot-v1'
         AND approver_authentication_acr IS NULL
         AND approver_authentication_utc IS NULL
         AND identity_issuer='http://localhost:8081/realms/temporalmark'
         AND approved_by_subject='00000000-0000-0000-0000-000000000004')
       OR
        (approver_assurance_kind='OIDC_ACR_ASSERTED'
         AND approval_policy_id='pinned-oidc-acr-v1'
         AND approver_authentication_acr IS NOT NULL
         AND char_length(approver_authentication_acr) BETWEEN 2 AND 255
         AND approver_authentication_acr=btrim(approver_authentication_acr)
         AND approver_authentication_acr !~ '[[:cntrl:]]'
         AND lower(approver_authentication_acr) NOT IN ('0','1','pwd','password','basic')
         AND approver_authentication_utc IS NOT NULL
         AND approver_authentication_utc<=approved_utc+interval '30 seconds'
         AND approver_authentication_utc>=approved_utc-interval '120 seconds')
    ))
  );

-- Old SECURITY DEFINER function remains available to the migration owner for
-- historical diagnostics only; unprivileged approver cannot execute it.
REVOKE ALL ON FUNCTION public.approve_enrollment(
    uuid,text,text,text,text,text,char(64)) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.approve_enrollment(
    uuid,text,text,text,text,text,char(64)) FROM temporalmark_approver_group;

CREATE FUNCTION public.approve_enrollment(
    request_id uuid, expected_name text, expected_issuer text,
    expected_operator_sub text, expected_admin_sub text,
    approver_sub text, approver_hash char(64),
    assurance_kind text, authentication_acr text, authentication_unix bigint)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    approved_id uuid;
    checked_at timestamptz := clock_timestamp();
    policy_id text;
BEGIN
    IF assurance_kind='OIDC_ACR_ASSERTED'
       AND authentication_acr IS NOT NULL
       AND char_length(authentication_acr) BETWEEN 2 AND 255
       AND authentication_acr=btrim(authentication_acr)
       AND authentication_acr !~ '[[:cntrl:]]'
       AND lower(authentication_acr) NOT IN ('0','1','pwd','password','basic')
       AND authentication_unix IS NOT NULL
       AND authentication_unix BETWEEN
           extract(epoch FROM checked_at)::bigint-120
           AND extract(epoch FROM checked_at)::bigint+30
    THEN
        policy_id := 'pinned-oidc-acr-v1';
    ELSIF assurance_kind='DISPOSABLE_PASSWORD_ONLY'
       AND expected_issuer='http://localhost:8081/realms/temporalmark'
       AND approver_sub='00000000-0000-0000-0000-000000000004'
       AND authentication_acr IS NULL AND authentication_unix IS NULL
    THEN
        policy_id := 'disposable-keycloak-pilot-v1';
    ELSE
        RAISE EXCEPTION 'Invalid or unavailable approval authentication evidence'
            USING ERRCODE='22023';
    END IF;

    IF approver_sub IS NULL OR char_length(approver_sub) NOT BETWEEN 1 AND 255
       OR approver_sub <> btrim(approver_sub) OR approver_sub ~ '[[:cntrl:]]'
       OR approver_hash IS NULL OR approver_hash !~ '^[0-9A-F]{64}$'
    THEN
        RAISE EXCEPTION 'Invalid approval metadata' USING ERRCODE='22023';
    END IF;

    UPDATE public.organization_enrollment_requests r
       SET approved_by_subject=approver_sub,
           approval_proof_sha256=approver_hash,
           approved_utc=checked_at,
           approver_assurance_kind=assurance_kind,
           approver_authentication_acr=authentication_acr,
           approver_authentication_utc=CASE
               WHEN authentication_unix IS NULL THEN NULL
               ELSE to_timestamp(authentication_unix)
           END,
           approval_policy_id=policy_id
     WHERE r.id=request_id AND r.organization_name=expected_name
       AND r.identity_issuer=expected_issuer
       AND r.operator_subject=expected_operator_sub
       AND r.first_admin_subject=expected_admin_sub
       AND r.operator_subject<>approver_sub AND r.first_admin_subject<>approver_sub
       AND r.approved_utc IS NULL AND r.consumed_utc IS NULL
       AND r.expires_utc>checked_at
     RETURNING r.id INTO approved_id;
    IF approved_id IS NULL THEN
        RAISE EXCEPTION 'Approval request missing, mismatched, expired or already approved'
            USING ERRCODE='23514';
    END IF;
    RETURN approved_id;
END;
$$;

REVOKE ALL ON FUNCTION public.approve_enrollment(
    uuid,text,text,text,text,text,char(64),text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.approve_enrollment(
    uuid,text,text,text,text,text,char(64),text,text,bigint) TO temporalmark_approver_group;

-- A pre-V008 approval is retained honestly as unverified history, but cannot
-- be *newly* consumed in a future enrollment.
CREATE FUNCTION public.reject_legacy_assurance_completion()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF NEW.consumed_utc IS NOT NULL AND OLD.consumed_utc IS NULL AND
       (NEW.approver_assurance_kind IS NULL OR
        NEW.approver_assurance_kind='LEGACY_UNVERIFIED') THEN
        RAISE EXCEPTION 'Unverified historical approval cannot activate tenant'
            USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_require_approval_assurance_for_completion
BEFORE UPDATE OF consumed_utc ON public.organization_enrollment_requests
FOR EACH ROW EXECUTE FUNCTION public.reject_legacy_assurance_completion();
REVOKE ALL ON FUNCTION public.reject_legacy_assurance_completion() FROM PUBLIC;
COMMENT ON COLUMN public.organization_enrollment_requests.approver_assurance_kind IS
'Pilot classification: OIDC_ACR_ASSERTED is signed IdP assertion, NOT independently verified MFA; DISPOSABLE_PASSWORD_ONLY is test-only; LEGACY_UNVERIFIED historic.';
