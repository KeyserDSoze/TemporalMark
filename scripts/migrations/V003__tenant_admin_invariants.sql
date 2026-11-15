-- V003: transactional tenant bootstrap and concurrency-safe active-admin invariant.
-- Applied under a migration transaction/advisory lock. Older local schemas are upgraded in place.
-- Existing SQL trigger protected deletions but did not protect organization creation or
-- concurrent decisions at commit. New deferred checks and parent-row writes cover both.

LOCK TABLE public.organizations, public.organization_memberships IN SHARE ROW EXCLUSIVE MODE;

-- Refuse to bless an already-invalid database; repair it under operator control first.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.organizations o
        WHERE o.is_active AND NOT EXISTS (
            SELECT 1 FROM public.organization_memberships m
            WHERE m.organization_id = o.id AND m.is_active AND m.role = 'tenant_admin'
        )
    ) THEN
        RAISE EXCEPTION 'Existing active organization without an active administrator; manual remediation required'
            USING ERRCODE = '23514';
    END IF;
END;
$$;

-- Every membership write modifies the parent tuple. Concurrent transactions on
-- different membership rows now serialize on the same organization row; at
-- REPEATABLE READ/ SERIALIZABLE a conflicting old snapshot must abort (40001).
ALTER TABLE public.organizations
    ADD COLUMN IF NOT EXISTS membership_epoch bigint NOT NULL DEFAULT 0;

DROP TRIGGER IF EXISTS trg_protect_last_admin ON public.organization_memberships;
DROP FUNCTION IF EXISTS public.protect_last_active_tenant_admin();

CREATE OR REPLACE FUNCTION public.serialize_membership_mutation()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    target_id uuid;
BEGIN
    IF TG_OP = 'UPDATE' AND OLD.organization_id IS DISTINCT FROM NEW.organization_id THEN
        -- Stable lock order for changes across two organizations.
        FOR target_id IN
            SELECT DISTINCT org_id FROM unnest(ARRAY[OLD.organization_id, NEW.organization_id]) AS ids(org_id)
            ORDER BY org_id
        LOOP
            UPDATE public.organizations
               SET membership_epoch = membership_epoch + 1
             WHERE id = target_id;
        END LOOP;
    ELSE
        target_id := CASE WHEN TG_OP = 'DELETE' THEN OLD.organization_id ELSE NEW.organization_id END;
        UPDATE public.organizations
           SET membership_epoch = membership_epoch + 1
         WHERE id = target_id;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_serialize_membership_mutation ON public.organization_memberships;
CREATE TRIGGER trg_serialize_membership_mutation
BEFORE INSERT OR UPDATE OR DELETE ON public.organization_memberships
FOR EACH ROW EXECUTE FUNCTION public.serialize_membership_mutation();

CREATE OR REPLACE FUNCTION public.assert_tenant_has_active_admin(target_org uuid)
RETURNS void LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM public.organizations o
         WHERE o.id = target_org AND o.is_active
           AND NOT EXISTS (
               SELECT 1 FROM public.organization_memberships m
                WHERE m.organization_id = o.id AND m.is_active
                  AND m.role = 'tenant_admin'
           )
    ) THEN
        RAISE EXCEPTION 'Active organization % must retain an active tenant administrator', target_org
            USING ERRCODE = '23514', CONSTRAINT = 'tenant_requires_active_admin';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION public.check_admin_after_organization_change()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM public.assert_tenant_has_active_admin(NEW.id);
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION public.check_admin_after_membership_change()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_OP = 'DELETE' OR TG_OP = 'UPDATE' THEN
        PERFORM public.assert_tenant_has_active_admin(OLD.organization_id);
    END IF;
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        PERFORM public.assert_tenant_has_active_admin(NEW.organization_id);
    END IF;
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS trg_deferred_organization_admin ON public.organizations;
CREATE CONSTRAINT TRIGGER trg_deferred_organization_admin
AFTER INSERT OR UPDATE OF is_active ON public.organizations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.check_admin_after_organization_change();

DROP TRIGGER IF EXISTS trg_deferred_membership_admin ON public.organization_memberships;
CREATE CONSTRAINT TRIGGER trg_deferred_membership_admin
AFTER INSERT OR UPDATE OR DELETE ON public.organization_memberships
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION public.check_admin_after_membership_change();

-- Controlled DBA/provisioner-only operation. The first admin subject MUST be
-- obtained by the operator from the verified OIDC issuer; SQL cannot verify
-- an arbitrary string against an external IdP. No public HTTP endpoint uses this.
CREATE OR REPLACE FUNCTION public.bootstrap_organization(
    organization_id uuid, organization_name text, first_admin_oidc_sub text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF organization_id IS NULL OR organization_id = '00000000-0000-0000-0000-000000000000'::uuid
        OR organization_name IS NULL
        OR char_length(btrim(organization_name)) NOT BETWEEN 1 AND 200
        OR organization_name <> btrim(organization_name)
        OR first_admin_oidc_sub IS NULL
        OR char_length(first_admin_oidc_sub) NOT BETWEEN 1 AND 255
        OR first_admin_oidc_sub <> btrim(first_admin_oidc_sub)
        OR first_admin_oidc_sub ~ '[[:cntrl:]]'
    THEN
        RAISE EXCEPTION 'Invalid organization or verified OIDC subject input'
            USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.organizations(id, display_name, is_active)
        VALUES (organization_id, organization_name, true);
    INSERT INTO public.organization_memberships(organization_id, subject_id, role, is_active)
        VALUES (organization_id, first_admin_oidc_sub, 'tenant_admin', true);
    RETURN organization_id;
END;
$$;
-- No EXECUTE for PUBLIC: operator grants EXECUTE to a separate privileged
-- provisioning role after external identity verification, NOT to the API role.
REVOKE ALL ON FUNCTION public.bootstrap_organization(uuid, text, text) FROM PUBLIC;
COMMENT ON FUNCTION public.bootstrap_organization(uuid, text, text) IS
    'Controlled operator enrollment only; caller must verify OIDC issuer/subject out of band.';
