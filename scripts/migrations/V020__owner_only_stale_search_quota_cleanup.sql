-- V020 — owner-invoked bounded removal of stale search admission counters.
-- Technical minimization only; NOT a scheduled GDPR erasure/retention policy.
-- V001..V019 are immutable. Do not touch timestamp receipts or audit evidence.
-- This routine is intentionally SECURITY INVOKER (default), NOT DEFINER.
CREATE FUNCTION public.purge_stale_imprint_search_rate_counters(p_batch integer)
RETURNS TABLE(principal_deleted integer, tenant_deleted integer)
LANGUAGE plpgsql SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_cutoff timestamptz;
BEGIN
    IF p_batch IS NULL OR p_batch < 1 OR p_batch > 500 THEN
        RAISE EXCEPTION 'Quota maintenance batch must be between 1 and 500'
            USING ERRCODE = '22023';
    END IF;

    -- Match V019's fixed UTC epoch-minute windows and strict stale cutoff.
    -- All time decisions come from PostgreSQL, not the operator's clock.
    v_cutoff := to_timestamp(
        (floor(extract(epoch FROM clock_timestamp()) / 60) * 60)::double precision
    ) - interval '3 minutes';

    -- One bounded, nonblocking batch of inactive actor-subject rows.
    -- SKIP LOCKED prevents deletion of a row being used by an active
    -- quota transaction; a later owner maintenance invocation may retry.
    WITH stale AS (
        SELECT organization_id, actor_subject_id
          FROM public.imprint_search_rate_principals
         WHERE window_start < v_cutoff
         ORDER BY window_start, organization_id, actor_subject_id
         LIMIT p_batch FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.imprint_search_rate_principals AS p USING stale
     WHERE p.organization_id = stale.organization_id
       AND p.actor_subject_id = stale.actor_subject_id
       AND p.window_start < v_cutoff;
    GET DIAGNOSTICS principal_deleted = ROW_COUNT;

    WITH stale AS (
        SELECT organization_id
          FROM public.imprint_search_rate_tenants
         WHERE window_start < v_cutoff
         ORDER BY window_start, organization_id
         LIMIT p_batch FOR UPDATE SKIP LOCKED
    )
    DELETE FROM public.imprint_search_rate_tenants AS t USING stale
     WHERE t.organization_id = stale.organization_id
       AND t.window_start < v_cutoff;
    GET DIAGNOSTICS tenant_deleted = ROW_COUNT;

    -- Only aggregate counts cross the administrative boundary. Neither
    -- organization IDs nor OIDC actor subjects ever appear in this result.
    RETURN NEXT;
END;
$$;

-- PostgreSQL grants EXECUTE to PUBLIC on new functions by default.
-- Revoke in the SAME migration transaction before any caller may execute.
-- The schema/migration owner retains ownership execution authority.
REVOKE ALL ON FUNCTION public.purge_stale_imprint_search_rate_counters(integer)
    FROM PUBLIC, temporalmark_runtime_group, temporalmark_provisioner_group,
         temporalmark_approver_group, temporalmark_credential_registrar_group;

COMMENT ON FUNCTION public.purge_stale_imprint_search_rate_counters(integer) IS
'OWNER-ONLY manual bounded stale search quota cleanup (1..500 per table). No actor identities in output; no scheduler, GDPR approval or deletion of timestamp evidence.';
