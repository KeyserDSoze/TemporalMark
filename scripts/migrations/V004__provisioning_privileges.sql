-- V004: limited-purpose data roles and durable proof-consumption record.
-- New groups do not have LOGIN; deployers create separate users with credentials via secret injection.
-- All security-definer routines retain pg_catalog,pg_temp search path.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'temporalmark_runtime_group') THEN
        CREATE ROLE temporalmark_runtime_group NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'temporalmark_provisioner_group') THEN
        CREATE ROLE temporalmark_provisioner_group NOLOGIN;
    END IF;
END $$;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO temporalmark_runtime_group, temporalmark_provisioner_group;
REVOKE ALL ON TABLE public.organizations, public.organization_memberships,
    public.timestamp_registry, public.tenant_audit_events FROM PUBLIC;
GRANT SELECT ON public.organizations, public.organization_memberships TO temporalmark_runtime_group;
GRANT SELECT, INSERT ON public.timestamp_registry, public.tenant_audit_events TO temporalmark_runtime_group;
REVOKE ALL ON FUNCTION public.bootstrap_organization(uuid,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.bootstrap_organization(uuid,text,text) FROM temporalmark_runtime_group;
REVOKE ALL ON FUNCTION public.bootstrap_organization(uuid,text,text) FROM temporalmark_provisioner_group;

CREATE TABLE IF NOT EXISTS public.organization_provisioning_events (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL UNIQUE REFERENCES public.organizations(id),
    first_admin_subject text NOT NULL CHECK (char_length(first_admin_subject) BETWEEN 1 AND 255
       AND first_admin_subject !~ '[[:cntrl:]]'),
    identity_issuer text NOT NULL CHECK (char_length(identity_issuer) BETWEEN 10 AND 1024
       AND identity_issuer !~ '[[:cntrl:]]'),
    provisioner_subject text NOT NULL CHECK (char_length(provisioner_subject) BETWEEN 1 AND 255
       AND provisioner_subject !~ '[[:cntrl:]]'),
    operator_proof_sha256 char(64) NOT NULL UNIQUE
        CHECK (operator_proof_sha256 ~ '^[0-9A-F]{64}$'),
    admin_proof_sha256 char(64) NOT NULL UNIQUE
        CHECK (admin_proof_sha256 ~ '^[0-9A-F]{64}$'),
    created_utc timestamptz NOT NULL DEFAULT now(),
    CHECK (first_admin_subject <> provisioner_subject)
);
-- This is a pilot append-only record, NOT legal WORM or an IdP revocation check.
CREATE OR REPLACE FUNCTION public.reject_provisioning_audit_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'Organization provisioning evidence is append-only';
END;
$$;
DROP TRIGGER IF EXISTS trg_provisioning_audit_append_only ON public.organization_provisioning_events;
CREATE TRIGGER trg_provisioning_audit_append_only
BEFORE UPDATE OR DELETE ON public.organization_provisioning_events
FOR EACH ROW EXECUTE FUNCTION public.reject_provisioning_audit_mutation();

-- Only the trusted operator command, after independent JWT checks, may call
-- this function. PostgreSQL cannot authenticate a token itself; possession of
-- the provisioning SQL credential remains a critical trust boundary.
CREATE OR REPLACE FUNCTION public.bootstrap_verified_organization(
    organization_id uuid, organization_name text, first_admin_subject text,
    identity_issuer text, provisioner_subject text,
    operator_proof_hash char(64), admin_proof_hash char(64))
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    result_id uuid;
BEGIN
    IF identity_issuer IS NULL OR char_length(identity_issuer) NOT BETWEEN 10 AND 1024
       OR identity_issuer !~ '^https?://' OR identity_issuer ~ '[[:cntrl:]]'
       OR provisioner_subject IS NULL OR char_length(provisioner_subject) NOT BETWEEN 1 AND 255
       OR provisioner_subject ~ '[[:cntrl:]]' OR first_admin_subject = provisioner_subject
       OR operator_proof_hash IS NULL OR operator_proof_hash !~ '^[0-9A-F]{64}$'
       OR admin_proof_hash IS NULL OR admin_proof_hash !~ '^[0-9A-F]{64}$'
    THEN
        RAISE EXCEPTION 'Invalid verified provisioning metadata' USING ERRCODE = '22023';
    END IF;
    result_id := public.bootstrap_organization(organization_id, organization_name, first_admin_subject);
    INSERT INTO public.organization_provisioning_events (
        id, organization_id, first_admin_subject, identity_issuer,
        provisioner_subject, operator_proof_sha256, admin_proof_sha256
    ) VALUES (
        gen_random_uuid(), result_id, first_admin_subject, identity_issuer,
        provisioner_subject, operator_proof_hash, admin_proof_hash
    );
    RETURN result_id;
END;
$$;
REVOKE ALL ON FUNCTION public.bootstrap_verified_organization(
    uuid,text,text,text,text,char(64),char(64)) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.bootstrap_verified_organization(
    uuid,text,text,text,text,char(64),char(64)) TO temporalmark_provisioner_group;
COMMENT ON FUNCTION public.bootstrap_verified_organization(
    uuid,text,text,text,text,char(64),char(64)) IS
'Only an independently secured caller validates signed OIDC proofs; one-time SHA256 proof consumption and audit are atomic.';

-- No SELECT/INSERT/UPDATE on organization/membership/audit to provisioning group.
-- No EXECUTE of bootstrap function to regular runtime group.
