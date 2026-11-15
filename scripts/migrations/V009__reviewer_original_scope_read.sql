-- V009: scope-limited, approved-reviewer-only read of the ORIGINAL pending enrollment.
-- Not a signature or independent human-consent protocol; #35 remains open.
-- No direct SELECT on pending requests is granted to approver, runtime or operator.
CREATE FUNCTION public.read_pending_enrollment(
    requested_id uuid, expected_issuer text, reviewer_sub text)
RETURNS TABLE(
    request_id uuid, organization_name text, identity_issuer text,
    operator_subject text, first_admin_subject text, expires_utc timestamptz)
LANGUAGE sql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
    SELECT r.id, r.organization_name, r.identity_issuer,
           r.operator_subject, r.first_admin_subject, r.expires_utc
    FROM public.organization_enrollment_requests AS r
    WHERE r.id = requested_id AND r.identity_issuer = expected_issuer
      AND reviewer_sub IS NOT NULL
      AND char_length(reviewer_sub) BETWEEN 1 AND 255
      AND reviewer_sub = btrim(reviewer_sub)
      AND reviewer_sub !~ '[[:cntrl:]]'
      AND reviewer_sub <> r.operator_subject
      AND reviewer_sub <> r.first_admin_subject
      AND r.approved_utc IS NULL AND r.consumed_utc IS NULL
      AND r.expires_utc > clock_timestamp()
$$;

REVOKE ALL ON FUNCTION public.read_pending_enrollment(uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.read_pending_enrollment(uuid,text,text)
    TO temporalmark_approver_group;
COMMENT ON FUNCTION public.read_pending_enrollment(uuid,text,text) IS
'Authorized restricted approver reads one unexpired original request; not independent human consent.';
