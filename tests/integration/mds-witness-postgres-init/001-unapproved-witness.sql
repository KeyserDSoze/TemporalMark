-- CI-only PostgreSQL 17 witness SERVICE on a separate Docker container
-- and named volume. These synthetic digests/serials are UNAPPROVED.
-- Never reuse test accounts/passwords or treat this as immutable WORM,
-- independent HSM/CAB operator custody or FIDO MDS provenance.
-- ADR 0038 / #69. This is NOT a TemporalMark main DB migration.
\set ON_ERROR_STOP on

CREATE ROLE temporalmark_witness_reader
    LOGIN PASSWORD 'local-witness-reader-only'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

REVOKE CONNECT ON DATABASE temporalmark_witness FROM PUBLIC;
GRANT CONNECT ON DATABASE temporalmark_witness
    TO temporalmark_witness_reader;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO temporalmark_witness_reader;

CREATE TABLE public.unapproved_witness_checkpoints
(
    source_policy_sha256 text COLLATE "C" PRIMARY KEY
        CHECK (source_policy_sha256 ~ '^[0-9A-F]{64}$'),
    candidate_serial bigint NOT NULL CHECK (candidate_serial > 0),
    seal_sha256 text COLLATE "C" NOT NULL
        CHECK (seal_sha256 ~ '^[0-9A-F]{64}$'),
    observed_utc timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE public.unapproved_witness_events
(
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_policy_sha256 text COLLATE "C" NOT NULL
        CHECK (source_policy_sha256 ~ '^[0-9A-F]{64}$'),
    candidate_serial bigint NOT NULL CHECK (candidate_serial > 0),
    seal_sha256 text COLLATE "C" NOT NULL
        CHECK (seal_sha256 ~ '^[0-9A-F]{64}$'),
    observed_utc timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (source_policy_sha256, candidate_serial)
);

-- Only the test witness owner/superuser can call the writer. A reader
-- cannot use this function, even though PostgreSQL grants EXECUTE on
-- new functions to PUBLIC by default unless explicitly revoked.
CREATE FUNCTION public.record_unapproved_highwater_witness(
    p_policy text, p_serial bigint, p_seal_sha256 text)
RETURNS text
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
DECLARE
    changed integer;
BEGIN
    IF p_policy IS NULL OR p_policy !~ '^[0-9A-F]{64}$' OR
       p_seal_sha256 IS NULL OR p_seal_sha256 !~ '^[0-9A-F]{64}$' OR
       p_serial IS NULL OR p_serial <= 0
    THEN
        RAISE EXCEPTION 'Invalid unapproved witness candidate'
          USING ERRCODE = '42501';
    END IF;

    -- Atomic PostgreSQL UPSERT serializes concurrent writers per scope.
    -- Only a STRICTLY higher version can replace an accepted candidate.
    INSERT INTO public.unapproved_witness_checkpoints AS state
        (source_policy_sha256, candidate_serial, seal_sha256)
    VALUES (p_policy, p_serial, p_seal_sha256)
    ON CONFLICT (source_policy_sha256)
    DO UPDATE
       SET candidate_serial = EXCLUDED.candidate_serial,
           seal_sha256 = EXCLUDED.seal_sha256,
           observed_utc = clock_timestamp()
    WHERE state.candidate_serial < EXCLUDED.candidate_serial;

    GET DIAGNOSTICS changed = ROW_COUNT;
    IF changed <> 1 THEN
        RAISE EXCEPTION 'Witness serial rollback or equivocation denied'
          USING ERRCODE = '42501';
    END IF;

    -- Appended in the SAME transaction. Not WORM: the witness owner
    -- could still DELETE/UPDATE rows or restore its own older backup.
    INSERT INTO public.unapproved_witness_events
        (source_policy_sha256, candidate_serial, seal_sha256)
    VALUES (p_policy, p_serial, p_seal_sha256);

    RETURN 'UNAPPROVED';
END;
$$;

REVOKE ALL ON TABLE
    public.unapproved_witness_checkpoints,
    public.unapproved_witness_events FROM PUBLIC;
REVOKE ALL ON FUNCTION
    public.record_unapproved_highwater_witness(text,bigint,text) FROM PUBLIC;

-- Production API, reviewer, registrar and main DB roles do not even
-- exist on this separate test instance. The ONLY non-owner permission:
GRANT SELECT ON TABLE public.unapproved_witness_checkpoints
    TO temporalmark_witness_reader;
