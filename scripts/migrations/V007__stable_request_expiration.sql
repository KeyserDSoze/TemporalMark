-- V007: derive both request timestamps from ONE database clock sample.
-- V006 used separate clock_timestamp() expressions, which can exceed the exact
-- 5-minute upper-bound check. Historical applied V006 remains immutable.
CREATE OR REPLACE FUNCTION public.request_enrollment(
    request_id uuid, requested_name text, expected_issuer text, operator_sub text,
    admin_sub text, request_operator_hash char(64), request_admin_hash char(64))
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    requested_at timestamptz := clock_timestamp();
BEGIN
    INSERT INTO public.organization_enrollment_requests
        (id,organization_name,identity_issuer,operator_subject,first_admin_subject,
         operator_request_sha256,admin_request_sha256,requested_utc,expires_utc)
    VALUES
        (request_id,requested_name,expected_issuer,operator_sub,admin_sub,
         request_operator_hash,request_admin_hash,requested_at,requested_at+interval '5 minutes');
    RETURN request_id;
END;
$$;
REVOKE ALL ON FUNCTION public.request_enrollment(
    uuid,text,text,text,text,char(64),char(64)) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.request_enrollment(
    uuid,text,text,text,text,char(64),char(64)) TO temporalmark_provisioner_group;
