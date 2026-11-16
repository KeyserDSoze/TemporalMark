-- V017 — STRICT OWNER-ONLY monotonic UNAPPROVED candidate staging.
-- This is NOT authenticated FIDO MDS metadata, CAB-pinned GlobalSign R46
-- trust, genuine CRL validation, production enrollment or durable WORM.
-- Independently signed source/rollback proof and DB backup-restore witness
-- remain release blockers under #61/#57/#55. V001–V016 are immutable.
-- No new LOGIN, role membership, grants to application groups, or API caller.

CREATE TABLE public.mds_unapproved_candidate_checkpoints (
    candidate_kind text NOT NULL
        CHECK (candidate_kind IN ('MDS_BLOB','ISSUER_CRL')),
    issuer_key_sha256 text NOT NULL
        CHECK (issuer_key_sha256 ~ '^[0-9A-F]{64}$'),
    source_policy_sha256 text NOT NULL
        CHECK (source_policy_sha256 ~ '^[0-9A-F]{64}$'),
    candidate_serial bigint NOT NULL CHECK (candidate_serial > 0),
    signed_evidence_sha256 text NOT NULL
        CHECK (signed_evidence_sha256 ~ '^[0-9A-F]{64}$'),
    change_reference text NOT NULL
        CHECK (char_length(change_reference) BETWEEN 8 AND 128
           AND change_reference=btrim(change_reference)
           AND change_reference !~ '[[:cntrl:]]'),
    observed_utc timestamptz NOT NULL,
    expires_utc timestamptz NOT NULL
        CHECK (expires_utc > observed_utc
           AND expires_utc <= observed_utc + interval '1 day'),
    review_status text NOT NULL DEFAULT 'UNAPPROVED'
        CHECK (review_status = 'UNAPPROVED'),
    PRIMARY KEY(candidate_kind,issuer_key_sha256)
);
REVOKE ALL ON TABLE public.mds_unapproved_candidate_checkpoints FROM
    PUBLIC,temporalmark_runtime_group,temporalmark_provisioner_group,
    temporalmark_approver_group,temporalmark_credential_registrar_group;
COMMENT ON TABLE public.mds_unapproved_candidate_checkpoints IS
'V017 owner-only UNAPPROVED version/digest checkpoint. Input is NOT independently verified signed FIDO metadata or CRL, SQL owner may modify, restore may roll back. No trust, signer enrollment, WORM or legal qualification.';

CREATE TABLE public.mds_unapproved_candidate_events (
    event_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    candidate_kind text NOT NULL
        CHECK (candidate_kind IN ('MDS_BLOB','ISSUER_CRL')),
    issuer_key_sha256 text NOT NULL
        CHECK (issuer_key_sha256 ~ '^[0-9A-F]{64}$'),
    source_policy_sha256 text NOT NULL
        CHECK (source_policy_sha256 ~ '^[0-9A-F]{64}$'),
    candidate_serial bigint NOT NULL CHECK (candidate_serial > 0),
    signed_evidence_sha256 text NOT NULL
        CHECK (signed_evidence_sha256 ~ '^[0-9A-F]{64}$'),
    change_reference text NOT NULL
        CHECK (char_length(change_reference) BETWEEN 8 AND 128
           AND change_reference=btrim(change_reference)
           AND change_reference !~ '[[:cntrl:]]'),
    observed_utc timestamptz NOT NULL,
    expires_utc timestamptz NOT NULL CHECK (expires_utc > observed_utc),
    review_status text NOT NULL DEFAULT 'UNAPPROVED'
        CHECK (review_status = 'UNAPPROVED')
);
CREATE INDEX idx_mds_unapproved_candidate_events_scope
    ON public.mds_unapproved_candidate_events
    (candidate_kind,issuer_key_sha256,candidate_serial);
REVOKE ALL ON TABLE public.mds_unapproved_candidate_events FROM
    PUBLIC,temporalmark_runtime_group,temporalmark_provisioner_group,
    temporalmark_approver_group,temporalmark_credential_registrar_group;
REVOKE ALL ON SEQUENCE public.mds_unapproved_candidate_events_event_id_seq FROM
    PUBLIC,temporalmark_runtime_group,temporalmark_provisioner_group,
    temporalmark_approver_group,temporalmark_credential_registrar_group;
COMMENT ON TABLE public.mds_unapproved_candidate_events IS
'V017 ordinary owner-controlled append-only-by-trigger candidate history; not signed, externally witnessed, tamper proof or WORM.';

CREATE FUNCTION public.block_mds_unapproved_candidate_event_change()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'V017 unapproved candidate history is append-only'
        USING ERRCODE='23514';
END;
$$;
REVOKE ALL ON FUNCTION public.block_mds_unapproved_candidate_event_change()
    FROM PUBLIC,temporalmark_runtime_group,temporalmark_provisioner_group,
         temporalmark_approver_group,temporalmark_credential_registrar_group;
CREATE TRIGGER trg_mds_unapproved_candidate_history_append_only
BEFORE UPDATE OR DELETE ON public.mds_unapproved_candidate_events
FOR EACH ROW EXECUTE FUNCTION public.block_mds_unapproved_candidate_event_change();

-- No SECURITY DEFINER: merely staging a claimed digest/serial must never
-- give an application login a way to write or launder untrusted values.
-- This checks the physical table-owner LOGIN as additional defense against
-- mistaken direct function EXECUTE grants or SET ROLE impersonation.
CREATE FUNCTION public.record_unapproved_mds_checkpoint_candidate(
    p_kind text,
    p_issuer_key_sha256 text,
    p_candidate_serial bigint,
    p_signed_evidence_sha256 text,
    p_source_policy_sha256 text,
    p_ttl_seconds integer,
    p_change_reference text
) RETURNS text
LANGUAGE plpgsql SECURITY INVOKER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    db_owner text;
    captured_utc timestamptz;
    expire_utc timestamptz;
    was_created boolean;
    existing public.mds_unapproved_candidate_checkpoints%ROWTYPE;
BEGIN
    SELECT pg_catalog.pg_get_userbyid(c.relowner)
      INTO db_owner
      FROM pg_catalog.pg_class AS c
     WHERE c.oid='public.mds_unapproved_candidate_checkpoints'::pg_catalog.regclass;

    IF db_owner IS NULL OR session_user<>db_owner OR current_user<>db_owner THEN
        RAISE EXCEPTION 'V017 candidates can only be staged by migration owner'
            USING ERRCODE='42501';
    END IF;

    IF p_kind IS NULL OR
       p_kind NOT IN ('MDS_BLOB','ISSUER_CRL') OR
       p_issuer_key_sha256 IS NULL OR
       p_issuer_key_sha256 !~ '^[0-9A-F]{64}$' OR
       p_source_policy_sha256 IS NULL OR
       p_source_policy_sha256 !~ '^[0-9A-F]{64}$' OR
       p_signed_evidence_sha256 IS NULL OR
       p_signed_evidence_sha256 !~ '^[0-9A-F]{64}$' OR
       p_candidate_serial IS NULL OR p_candidate_serial<=0 OR
       p_ttl_seconds IS NULL OR p_ttl_seconds NOT BETWEEN 60 AND 86400 OR
       p_change_reference IS NULL OR
       char_length(p_change_reference) NOT BETWEEN 8 AND 128 OR
       p_change_reference<>btrim(p_change_reference) OR
       p_change_reference ~ '[[:cntrl:]]'
    THEN
        RAISE EXCEPTION 'Invalid UNAPPROVED MDS/CRL candidate checkpoint input'
            USING ERRCODE='22023';
    END IF;

    captured_utc := clock_timestamp();
    expire_utc := captured_utc + make_interval(secs=>p_ttl_seconds);

    -- Unique (kind,issuer) index arbitrates new concurrent writers. When a
    -- conflict is encountered, SELECT FOR UPDATE below obtains the row
    -- lock and reads the latest committed serial before any change. No
    -- last-write-wins overwrite of conflicting signed-evidence digests.
    INSERT INTO public.mds_unapproved_candidate_checkpoints
      (candidate_kind,issuer_key_sha256,source_policy_sha256,
       candidate_serial,signed_evidence_sha256,change_reference,
       observed_utc,expires_utc)
    VALUES
      (p_kind,p_issuer_key_sha256,p_source_policy_sha256,
       p_candidate_serial,p_signed_evidence_sha256,p_change_reference,
       captured_utc,expire_utc)
    ON CONFLICT (candidate_kind,issuer_key_sha256) DO NOTHING
    RETURNING true INTO was_created;

    IF was_created IS TRUE THEN
        INSERT INTO public.mds_unapproved_candidate_events
          (candidate_kind,issuer_key_sha256,source_policy_sha256,
           candidate_serial,signed_evidence_sha256,change_reference,
           observed_utc,expires_utc)
        VALUES
          (p_kind,p_issuer_key_sha256,p_source_policy_sha256,
           p_candidate_serial,p_signed_evidence_sha256,p_change_reference,
           captured_utc,expire_utc);
        RETURN 'UNAPPROVED';
    END IF;

    SELECT * INTO existing
      FROM public.mds_unapproved_candidate_checkpoints
     WHERE candidate_kind=p_kind AND issuer_key_sha256=p_issuer_key_sha256
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Concurrent candidate record disappeared'
            USING ERRCODE='23514';
    END IF;

    -- Owner can simulate a stale backup, clock shift or recovery in tests.
    -- An expired or future-observed snapshot cannot be "rescued" by a
    -- higher serial without a separately approved reconciliation protocol.
    IF existing.review_status<>'UNAPPROVED' OR
       existing.expires_utc<=captured_utc OR
       existing.observed_utc>captured_utc OR
       existing.source_policy_sha256<>p_source_policy_sha256 OR
       p_candidate_serial<existing.candidate_serial OR
       (p_candidate_serial=existing.candidate_serial AND
        existing.signed_evidence_sha256<>p_signed_evidence_sha256)
    THEN
        RAISE EXCEPTION 'MDS/CRL candidate rollback, equivocation, expiry or provenance change'
            USING ERRCODE='23514';
    END IF;

    -- Idempotency never extends the previous validity period or invents
    -- a second observed event, even when a longer TTL is submitted.
    IF p_candidate_serial=existing.candidate_serial THEN
        RETURN 'UNAPPROVED';
    END IF;

    UPDATE public.mds_unapproved_candidate_checkpoints
       SET candidate_serial=p_candidate_serial,
           signed_evidence_sha256=p_signed_evidence_sha256,
           observed_utc=captured_utc,
           expires_utc=expire_utc,
           change_reference=p_change_reference
     WHERE candidate_kind=p_kind AND issuer_key_sha256=p_issuer_key_sha256;

    INSERT INTO public.mds_unapproved_candidate_events
      (candidate_kind,issuer_key_sha256,source_policy_sha256,
       candidate_serial,signed_evidence_sha256,change_reference,
       observed_utc,expires_utc)
    VALUES
      (p_kind,p_issuer_key_sha256,p_source_policy_sha256,
       p_candidate_serial,p_signed_evidence_sha256,p_change_reference,
       captured_utc,expire_utc);
    RETURN 'UNAPPROVED';
END;
$$;

REVOKE ALL ON FUNCTION public.record_unapproved_mds_checkpoint_candidate(
    text,text,bigint,text,text,integer,text)
    FROM PUBLIC,temporalmark_runtime_group,temporalmark_provisioner_group,
         temporalmark_approver_group,temporalmark_credential_registrar_group;

-- A migration must abort instead of silently advertising the interlock if
-- some group still has a direct or inherited accidental grant.
DO $$
DECLARE
    target_role text;
BEGIN
    FOREACH target_role IN ARRAY ARRAY[
       'temporalmark_runtime_group',
       'temporalmark_provisioner_group',
       'temporalmark_approver_group',
       'temporalmark_credential_registrar_group'
    ] LOOP
        IF pg_catalog.has_function_privilege(target_role,
            'public.record_unapproved_mds_checkpoint_candidate(text,text,bigint,text,text,integer,text)',
            'EXECUTE') OR
           pg_catalog.has_table_privilege(target_role,
            'public.mds_unapproved_candidate_checkpoints','SELECT') OR
           pg_catalog.has_table_privilege(target_role,
            'public.mds_unapproved_candidate_events','INSERT')
        THEN
            RAISE EXCEPTION 'V017 unapproved candidate staging privilege interlock failed'
                USING ERRCODE='42501';
        END IF;
    END LOOP;
END;
$$;

COMMENT ON FUNCTION public.record_unapproved_mds_checkpoint_candidate(
    text,text,bigint,text,text,integer,text) IS
'V017 migration-owner-only UNAPPROVED claimed signed-data SHA256/serial staging. Hash is caller-supplied and NOT cryptographically checked or independently witnessed; rejects rollback/equivocation only within this untrusted PostgreSQL database primary. No FIDO MDS trust, CRL proof, credential activation, WORM or qualified service.';
