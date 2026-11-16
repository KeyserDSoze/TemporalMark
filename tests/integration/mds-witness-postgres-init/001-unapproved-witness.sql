-- CI-only PostgreSQL 17 witness SERVICE on a separate Docker container
-- and named volume. These synthetic digests/serials are UNAPPROVED.
-- Never reuse test accounts/passwords or treat this as immutable WORM,
-- independent HSM/CAB operator custody or FIDO MDS provenance.
-- ADR 0038 / #69. This is NOT a TemporalMark main DB migration.
\set ON_ERROR_STOP on

-- One bootstrap transaction: SECURITY DEFINER and PUBLIC revoke must
-- become visible atomically, without a PUBLIC EXECUTE permission window.
BEGIN;

CREATE ROLE temporalmark_witness_data_owner
    NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

CREATE ROLE temporalmark_witness_writer
    LOGIN PASSWORD 'local-witness-writer-only'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

CREATE ROLE temporalmark_witness_reader
    LOGIN PASSWORD 'local-witness-reader-only'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

-- Revoke BOTH PUBLIC CONNECT and TEMPORARY (default), because an
-- untrusted writer must not create pg_temp objects to try name masking.
REVOKE ALL ON DATABASE temporalmark_witness FROM PUBLIC;
GRANT CONNECT ON DATABASE temporalmark_witness
    TO temporalmark_witness_reader, temporalmark_witness_writer;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public
    TO temporalmark_witness_reader, temporalmark_witness_writer,
       temporalmark_witness_data_owner;

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

-- The ONLY unprivileged writer path is a carefully constrained
-- SECURITY DEFINER owned by a separate non-login, non-superuser role.
-- No untrusted dynamic SQL, all tables schema-qualified and a trusted
-- fixed search_path (pg_temp LAST). PostgreSQL's PUBLIC EXECUTE default
-- is revoked BEFORE this bootstrap transaction commits.
CREATE FUNCTION public.record_unapproved_highwater_witness(
    p_policy text, p_serial bigint, p_seal_sha256 text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
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


-- CI-only, non-authorizing, read-only append history reconciliation.
-- Limits per-policy traversal to 129 events; deny 129 or more.
CREATE FUNCTION public.check_unapproved_witness_history(
    p_policy text, p_serial bigint, p_seal_sha256 text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $
DECLARE
    item record;
    seen integer := 0;
    previous_serial bigint := 0;
    previous_observed timestamptz := '-infinity'::timestamptz;
    last_sha text := NULL;
BEGIN
    IF p_policy IS NULL OR p_policy !~ '^[0-9A-F]{64}, NOT by
-- the connected writer. It is impossible for the writer to SET ROLE
-- to this owner: no role membership is ever granted.
ALTER TABLE public.unapproved_witness_checkpoints
    OWNER TO temporalmark_witness_data_owner;
ALTER TABLE public.unapproved_witness_events
    OWNER TO temporalmark_witness_data_owner;
ALTER FUNCTION public.record_unapproved_highwater_witness(text,bigint,text)
    OWNER TO temporalmark_witness_data_owner;
ALTER FUNCTION public.check_unapproved_witness_history(text,bigint,text)
    OWNER TO temporalmark_witness_data_owner;

-- Secure any future routines explicitly created by the non-login
-- data-owner, in addition to revoking THIS routine below.
ALTER DEFAULT PRIVILEGES FOR ROLE temporalmark_witness_data_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

REVOKE ALL ON TABLE
    public.unapproved_witness_checkpoints,
    public.unapproved_witness_events FROM PUBLIC;
REVOKE ALL ON FUNCTION
    public.record_unapproved_highwater_witness(text,bigint,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION
    public.check_unapproved_witness_history(text,bigint,text) FROM PUBLIC;
REVOKE ALL ON SEQUENCE
    public.unapproved_witness_events_event_id_seq FROM PUBLIC;

-- Read-only witness operator may SELECT the latest row only.
GRANT SELECT ON TABLE public.unapproved_witness_checkpoints
    TO temporalmark_witness_reader;

-- Separate non-superuser writer may only EXECUTE this ONE restricted,
-- atomic append function; it has NO direct table/event/sequence
-- privilege and NO membership in the non-login data-owner.
GRANT EXECUTE ON FUNCTION
    public.record_unapproved_highwater_witness(text,bigint,text)
    TO temporalmark_witness_writer;

-- The reader can only invoke this bounded checker. It cannot SELECT
-- the event table, and the restricted writer cannot invoke the checker.
GRANT EXECUTE ON FUNCTION
    public.check_unapproved_witness_history(text,bigint,text)
    TO temporalmark_witness_reader;

COMMIT;
 OR
       p_seal_sha256 IS NULL OR p_seal_sha256 !~ '^[0-9A-F]{64}, NOT by
-- the connected writer. It is impossible for the writer to SET ROLE
-- to this owner: no role membership is ever granted.
ALTER TABLE public.unapproved_witness_checkpoints
    OWNER TO temporalmark_witness_data_owner;
ALTER TABLE public.unapproved_witness_events
    OWNER TO temporalmark_witness_data_owner;
ALTER FUNCTION public.record_unapproved_highwater_witness(text,bigint,text)
    OWNER TO temporalmark_witness_data_owner;

-- Secure any future routines explicitly created by the non-login
-- data-owner, in addition to revoking THIS routine below.
ALTER DEFAULT PRIVILEGES FOR ROLE temporalmark_witness_data_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

REVOKE ALL ON TABLE
    public.unapproved_witness_checkpoints,
    public.unapproved_witness_events FROM PUBLIC;
REVOKE ALL ON FUNCTION
    public.record_unapproved_highwater_witness(text,bigint,text) FROM PUBLIC;
REVOKE ALL ON SEQUENCE
    public.unapproved_witness_events_event_id_seq FROM PUBLIC;

-- Read-only witness operator may SELECT the latest row only.
GRANT SELECT ON TABLE public.unapproved_witness_checkpoints
    TO temporalmark_witness_reader;

-- Separate non-superuser writer may only EXECUTE this ONE restricted,
-- atomic append function; it has NO direct table/event/sequence
-- privilege and NO membership in the non-login data-owner.
GRANT EXECUTE ON FUNCTION
    public.record_unapproved_highwater_witness(text,bigint,text)
    TO temporalmark_witness_writer;

COMMIT;
 OR
       p_serial IS NULL OR p_serial <= 0 THEN
        RETURN false;
    END IF;

    FOR item IN
        SELECT candidate_serial, seal_sha256, observed_utc
        FROM public.unapproved_witness_events
        WHERE source_policy_sha256 = p_policy
        ORDER BY event_id
        LIMIT 129
    LOOP
        seen := seen + 1;
        IF seen > 128 OR item.candidate_serial IS NULL OR
           item.candidate_serial <= previous_serial OR
           item.seal_sha256 IS NULL OR
           item.seal_sha256 !~ '^[0-9A-F]{64}, NOT by
-- the connected writer. It is impossible for the writer to SET ROLE
-- to this owner: no role membership is ever granted.
ALTER TABLE public.unapproved_witness_checkpoints
    OWNER TO temporalmark_witness_data_owner;
ALTER TABLE public.unapproved_witness_events
    OWNER TO temporalmark_witness_data_owner;
ALTER FUNCTION public.record_unapproved_highwater_witness(text,bigint,text)
    OWNER TO temporalmark_witness_data_owner;

-- Secure any future routines explicitly created by the non-login
-- data-owner, in addition to revoking THIS routine below.
ALTER DEFAULT PRIVILEGES FOR ROLE temporalmark_witness_data_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

REVOKE ALL ON TABLE
    public.unapproved_witness_checkpoints,
    public.unapproved_witness_events FROM PUBLIC;
REVOKE ALL ON FUNCTION
    public.record_unapproved_highwater_witness(text,bigint,text) FROM PUBLIC;
REVOKE ALL ON SEQUENCE
    public.unapproved_witness_events_event_id_seq FROM PUBLIC;

-- Read-only witness operator may SELECT the latest row only.
GRANT SELECT ON TABLE public.unapproved_witness_checkpoints
    TO temporalmark_witness_reader;

-- Separate non-superuser writer may only EXECUTE this ONE restricted,
-- atomic append function; it has NO direct table/event/sequence
-- privilege and NO membership in the non-login data-owner.
GRANT EXECUTE ON FUNCTION
    public.record_unapproved_highwater_witness(text,bigint,text)
    TO temporalmark_witness_writer;

COMMIT;
 OR
           item.observed_utc IS NULL OR
           NOT pg_catalog.isfinite(item.observed_utc) OR
           item.observed_utc < previous_observed THEN
            RETURN false;
        END IF;
        previous_serial := item.candidate_serial;
        previous_observed := item.observed_utc;
        last_sha := item.seal_sha256;
    END LOOP;

    RETURN seen BETWEEN 1 AND 128 AND
           previous_serial = p_serial AND last_sha = p_seal_sha256 AND
           EXISTS (
               SELECT 1 FROM public.unapproved_witness_checkpoints
               WHERE source_policy_sha256 = p_policy
                 AND candidate_serial = p_serial
                 AND seal_sha256 = p_seal_sha256
           );
END;
$;

-- These objects are owned by a NOLOGIN and NOSUPERUSER role, NOT by
-- the connected writer. It is impossible for the writer to SET ROLE
-- to this owner: no role membership is ever granted.
ALTER TABLE public.unapproved_witness_checkpoints
    OWNER TO temporalmark_witness_data_owner;
ALTER TABLE public.unapproved_witness_events
    OWNER TO temporalmark_witness_data_owner;
ALTER FUNCTION public.record_unapproved_highwater_witness(text,bigint,text)
    OWNER TO temporalmark_witness_data_owner;

-- Secure any future routines explicitly created by the non-login
-- data-owner, in addition to revoking THIS routine below.
ALTER DEFAULT PRIVILEGES FOR ROLE temporalmark_witness_data_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

REVOKE ALL ON TABLE
    public.unapproved_witness_checkpoints,
    public.unapproved_witness_events FROM PUBLIC;
REVOKE ALL ON FUNCTION
    public.record_unapproved_highwater_witness(text,bigint,text) FROM PUBLIC;
REVOKE ALL ON SEQUENCE
    public.unapproved_witness_events_event_id_seq FROM PUBLIC;

-- Read-only witness operator may SELECT the latest row only.
GRANT SELECT ON TABLE public.unapproved_witness_checkpoints
    TO temporalmark_witness_reader;

-- Separate non-superuser writer may only EXECUTE this ONE restricted,
-- atomic append function; it has NO direct table/event/sequence
-- privilege and NO membership in the non-login data-owner.
GRANT EXECUTE ON FUNCTION
    public.record_unapproved_highwater_witness(text,bigint,text)
    TO temporalmark_witness_writer;

COMMIT;
