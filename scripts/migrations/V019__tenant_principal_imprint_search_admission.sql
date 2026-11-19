-- V019 — pilot tenant+principal imprint-search admission via shared PostgreSQL primary.
-- No document hash, raw JWT, request body or result metadata in rate tables.
-- Separate SQL storage is not immutable audit, GDPR retention proof or eIDAS trust.
CREATE TABLE public.imprint_search_rate_tenants (
    organization_id uuid PRIMARY KEY REFERENCES public.organizations(id) ON DELETE CASCADE,
    window_start timestamptz NOT NULL,
    hits integer NOT NULL CHECK (hits BETWEEN 0 AND 30)
);
CREATE INDEX ix_imprint_search_rate_tenants_stale
    ON public.imprint_search_rate_tenants(window_start);

CREATE TABLE public.imprint_search_rate_principals (
    organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    actor_subject_id text NOT NULL
        CHECK (char_length(actor_subject_id) BETWEEN 1 AND 255 AND
               actor_subject_id = btrim(actor_subject_id) AND
               actor_subject_id !~ '[[:cntrl:]]'),
    window_start timestamptz NOT NULL,
    hits integer NOT NULL CHECK (hits BETWEEN 0 AND 12),
    PRIMARY KEY (organization_id, actor_subject_id)
);
CREATE INDEX ix_imprint_search_rate_principals_stale
    ON public.imprint_search_rate_principals(window_start);

REVOKE ALL ON public.imprint_search_rate_tenants,
              public.imprint_search_rate_principals FROM PUBLIC;
REVOKE ALL ON public.imprint_search_rate_tenants,
              public.imprint_search_rate_principals FROM temporalmark_runtime_group;

-- One tenant-level transaction advisory lock serializes all principals' quota
-- checks. Hash collisions can only over-serialize DIFFERENT tenant IDs, not
-- merge counters. The lock is transaction-scoped and auto-releases on errors.
-- All app instances MUST share the SAME writable PostgreSQL primary.
CREATE FUNCTION public.consume_imprint_search_rate(p_org uuid, p_actor text)
RETURNS TABLE(allowed boolean, retry_after_seconds integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_window timestamptz;
    v_org_window timestamptz;
    v_actor_window timestamptz;
    v_org_hits integer;
    v_actor_hits integer;
    v_retry integer;
BEGIN
    IF p_org IS NULL OR p_org = '00000000-0000-0000-0000-000000000000'::uuid
       OR p_actor IS NULL OR char_length(p_actor) NOT BETWEEN 1 AND 255
       OR p_actor <> btrim(p_actor) OR p_actor ~ '[[:cntrl:]]'
    THEN
        RAISE EXCEPTION 'Invalid authenticated quota scope' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(115116, hashtext(p_org::text));
    -- The database clock, not caller or local application clocks, owns windows.
    v_window := to_timestamp(
        (floor(extract(epoch FROM clock_timestamp()) / 60) * 60)::double precision);

    -- Incrementally discard stale identities. This is NOT a guaranteed TTL;
    -- idle rows still require a separately approved maintenance/retention job.
    WITH stale AS (
        SELECT organization_id, actor_subject_id
          FROM public.imprint_search_rate_principals
         WHERE window_start < v_window - interval '3 minutes'
         ORDER BY window_start
         LIMIT 32 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.imprint_search_rate_principals AS t USING stale
     WHERE t.organization_id=stale.organization_id
       AND t.actor_subject_id=stale.actor_subject_id;

    WITH stale AS (
        SELECT organization_id FROM public.imprint_search_rate_tenants
         WHERE window_start < v_window - interval '3 minutes'
         ORDER BY window_start
         LIMIT 16 FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.imprint_search_rate_tenants AS t USING stale
     WHERE t.organization_id=stale.organization_id;

    INSERT INTO public.imprint_search_rate_tenants(organization_id,window_start,hits)
    VALUES (p_org,v_window,0) ON CONFLICT(organization_id) DO NOTHING;

    SELECT t.window_start,t.hits INTO v_org_window,v_org_hits
      FROM public.imprint_search_rate_tenants t
     WHERE t.organization_id=p_org FOR UPDATE;
    IF v_org_window IS NULL OR v_org_hits IS NULL OR
       v_org_window > v_window OR v_org_hits NOT BETWEEN 0 AND 30
    THEN
        RAISE EXCEPTION 'Tenant quota state invalid or database clock rolled back'
          USING ERRCODE='22023';
    END IF;
    IF v_org_window < v_window THEN
        UPDATE public.imprint_search_rate_tenants
           SET window_start=v_window,hits=0 WHERE organization_id=p_org;
        v_org_hits := 0;
    END IF;

    INSERT INTO public.imprint_search_rate_principals(
        organization_id,actor_subject_id,window_start,hits)
    VALUES (p_org,p_actor,v_window,0)
    ON CONFLICT(organization_id,actor_subject_id) DO NOTHING;

    SELECT p.window_start,p.hits INTO v_actor_window,v_actor_hits
      FROM public.imprint_search_rate_principals p
     WHERE p.organization_id=p_org AND p.actor_subject_id=p_actor FOR UPDATE;
    IF v_actor_window IS NULL OR v_actor_hits IS NULL OR
       v_actor_window > v_window OR v_actor_hits NOT BETWEEN 0 AND 12
    THEN
        RAISE EXCEPTION 'Actor quota state invalid or database clock rolled back'
          USING ERRCODE='22023';
    END IF;
    IF v_actor_window < v_window THEN
        UPDATE public.imprint_search_rate_principals
           SET window_start=v_window,hits=0
         WHERE organization_id=p_org AND actor_subject_id=p_actor;
        v_actor_hits := 0;
    END IF;

    IF v_org_hits >= 30 OR v_actor_hits >= 12 THEN
        v_retry := greatest(1,least(60,
            ceil(extract(epoch FROM
                (v_window + interval '1 minute' - clock_timestamp())))::integer));
        RETURN QUERY SELECT false, v_retry;
        RETURN;
    END IF;

    UPDATE public.imprint_search_rate_tenants
       SET hits=hits+1 WHERE organization_id=p_org;
    UPDATE public.imprint_search_rate_principals
       SET hits=hits+1 WHERE organization_id=p_org AND actor_subject_id=p_actor;
    RETURN QUERY SELECT true,0;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_imprint_search_rate(uuid,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.consume_imprint_search_rate(uuid,text)
    FROM temporalmark_provisioner_group, temporalmark_approver_group,
         temporalmark_credential_registrar_group;
GRANT EXECUTE ON FUNCTION public.consume_imprint_search_rate(uuid,text)
    TO temporalmark_runtime_group;

COMMENT ON FUNCTION public.consume_imprint_search_rate(uuid,text) IS
'Pilot fixed 60-second PostgreSQL search quota: 12 per subject, 30 per tenant. Not source document evidence or WORM. Requires shared primary.';
