-- V010 — Terminal independent reviewer REJECT decision (pilot, NOT a human signature).
-- All previous migration files are immutable. PostgreSQL row locking ensures
-- approve/reject races serialize on the same original pending request.
ALTER TABLE public.organization_enrollment_requests
    ADD COLUMN rejected_by_subject text,
    ADD COLUMN rejected_utc timestamptz,
    ADD COLUMN rejection_proof_sha256 char(64),
    ADD COLUMN rejection_review_sha256 char(64),
    ADD COLUMN rejection_reason_code text;

ALTER TABLE public.organization_enrollment_requests
    ADD CONSTRAINT ck_enrollment_terminal_rejection CHECK (
        (rejected_utc IS NULL
         AND rejected_by_subject IS NULL
         AND rejection_proof_sha256 IS NULL
         AND rejection_review_sha256 IS NULL
         AND rejection_reason_code IS NULL)
        OR
        (rejected_utc IS NOT NULL
         AND approved_utc IS NULL
         AND consumed_utc IS NULL
         AND rejected_by_subject IS NOT NULL
         AND char_length(rejected_by_subject) BETWEEN 1 AND 255
         AND rejected_by_subject = btrim(rejected_by_subject)
         AND rejected_by_subject !~ '[[:cntrl:]]'
         AND rejected_by_subject <> operator_subject
         AND rejected_by_subject <> first_admin_subject
         AND rejection_proof_sha256 ~ '^[0-9A-F]{64}$'
         AND rejection_review_sha256 ~ '^[0-9A-F]{64}$'
         AND rejection_reason_code IN
              ('UNVERIFIED_ORGANIZATION','UNVERIFIED_IDENTITY','SCOPE_MISMATCH','POLICY_DENIED'))
    );
CREATE UNIQUE INDEX uq_enrollment_rejection_proof
    ON public.organization_enrollment_requests (rejection_proof_sha256)
    WHERE rejection_proof_sha256 IS NOT NULL;

-- One token proof may authorize at most ONE reviewer decision across BOTH types.
-- Backfill historical approval token digests without revising their assurance label.
CREATE TABLE public.organization_reviewer_decision_proofs (
    token_sha256 char(64) PRIMARY KEY CHECK (token_sha256 ~ '^[0-9A-F]{64}$'),
    request_id uuid NOT NULL UNIQUE REFERENCES public.organization_enrollment_requests(id),
    decision text NOT NULL CHECK (decision IN ('APPROVED','REJECTED')),
    recorded_utc timestamptz NOT NULL
);
INSERT INTO public.organization_reviewer_decision_proofs
    (token_sha256, request_id, decision, recorded_utc)
SELECT approval_proof_sha256, id, 'APPROVED', approved_utc
FROM public.organization_enrollment_requests
WHERE approved_utc IS NOT NULL AND approval_proof_sha256 IS NOT NULL;

-- SECURITY DEFINER trigger collects both signed JWT SHA-256 replay proofs
-- in the SAME transaction as the terminal status update. Unique PK blocks
-- reusing a token hash to approve then reject a different pending request.
CREATE FUNCTION public.record_enrollment_decision_proof()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF OLD.approved_utc IS NULL AND NEW.approved_utc IS NOT NULL THEN
        INSERT INTO public.organization_reviewer_decision_proofs
            (token_sha256,request_id,decision,recorded_utc)
        VALUES (NEW.approval_proof_sha256,NEW.id,'APPROVED',NEW.approved_utc);
    ELSIF OLD.rejected_utc IS NULL AND NEW.rejected_utc IS NOT NULL THEN
        INSERT INTO public.organization_reviewer_decision_proofs
            (token_sha256,request_id,decision,recorded_utc)
        VALUES (NEW.rejection_proof_sha256,NEW.id,'REJECTED',NEW.rejected_utc);
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION public.record_enrollment_decision_proof() FROM PUBLIC;

CREATE TRIGGER trg_reviewer_single_use_token_proof
AFTER UPDATE OF approved_utc,rejected_utc ON public.organization_enrollment_requests
FOR EACH ROW
WHEN (OLD.approved_utc IS DISTINCT FROM NEW.approved_utc
      OR OLD.rejected_utc IS DISTINCT FROM NEW.rejected_utc)
EXECUTE FUNCTION public.record_enrollment_decision_proof();

-- Never expose rejection as an HTTP endpoint; only the restricted SQL reviewer
-- role may invoke this narrow, scope-pinned, one-row terminal transition.
CREATE FUNCTION public.reject_enrollment(
    requested_id uuid, expected_name text, expected_issuer text,
    expected_operator_sub text, expected_admin_sub text, reviewer_sub text,
    reviewer_proof char(64), reviewed_scope char(64), reason_code text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    rejected_id uuid;
    now_utc timestamptz := clock_timestamp();
BEGIN
    IF reviewer_sub IS NULL OR char_length(reviewer_sub) NOT BETWEEN 1 AND 255
       OR reviewer_sub <> btrim(reviewer_sub)
       OR reviewer_sub ~ '[[:cntrl:]]'
       OR reviewer_proof IS NULL OR reviewer_proof !~ '^[0-9A-F]{64}$'
       OR reviewed_scope IS NULL OR reviewed_scope !~ '^[0-9A-F]{64}$'
       OR reason_code IS NULL OR reason_code NOT IN
           ('UNVERIFIED_ORGANIZATION','UNVERIFIED_IDENTITY',
            'SCOPE_MISMATCH','POLICY_DENIED')
    THEN
        RAISE EXCEPTION 'Invalid reviewer rejection decision' USING ERRCODE='22023';
    END IF;

    UPDATE public.organization_enrollment_requests r
       SET rejected_by_subject=reviewer_sub,
           rejected_utc=now_utc,
           rejection_proof_sha256=reviewer_proof,
           rejection_review_sha256=reviewed_scope,
           rejection_reason_code=reason_code
     WHERE r.id=requested_id
       AND r.organization_name=expected_name
       AND r.identity_issuer=expected_issuer
       AND r.operator_subject=expected_operator_sub
       AND r.first_admin_subject=expected_admin_sub
       AND reviewer_sub<>r.operator_subject AND reviewer_sub<>r.first_admin_subject
       AND r.approved_utc IS NULL AND r.rejected_utc IS NULL
       AND r.consumed_utc IS NULL AND r.expires_utc>now_utc
     RETURNING r.id INTO rejected_id;
    IF rejected_id IS NULL THEN
        RAISE EXCEPTION 'No active independent-review request can be rejected'
            USING ERRCODE='23514';
    END IF;
    RETURN rejected_id;
END;
$$;
REVOKE ALL ON FUNCTION public.reject_enrollment(
    uuid,text,text,text,text,text,char(64),char(64),text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.reject_enrollment(
    uuid,text,text,text,text,text,char(64),char(64),text)
    TO temporalmark_approver_group;

-- Re-define only the V009 read function through a new versioned migration.
-- Rejection removes a request from the view *immediately* after transaction.
CREATE OR REPLACE FUNCTION public.read_pending_enrollment(
    requested_id uuid, expected_issuer text, reviewer_sub text)
RETURNS TABLE(
    request_id uuid, organization_name text, identity_issuer text,
    operator_subject text, first_admin_subject text, expires_utc timestamptz)
LANGUAGE sql SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
    SELECT r.id,r.organization_name,r.identity_issuer,
           r.operator_subject,r.first_admin_subject,r.expires_utc
    FROM public.organization_enrollment_requests AS r
    WHERE r.id=requested_id AND r.identity_issuer=expected_issuer
      AND reviewer_sub IS NOT NULL
      AND char_length(reviewer_sub) BETWEEN 1 AND 255
      AND reviewer_sub=btrim(reviewer_sub)
      AND reviewer_sub !~ '[[:cntrl:]]'
      AND reviewer_sub<>r.operator_subject AND reviewer_sub<>r.first_admin_subject
      AND r.approved_utc IS NULL AND r.rejected_utc IS NULL
      AND r.consumed_utc IS NULL AND r.expires_utc>clock_timestamp()
$$;
REVOKE ALL ON FUNCTION public.read_pending_enrollment(uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.read_pending_enrollment(uuid,text,text)
    TO temporalmark_approver_group;
COMMENT ON COLUMN public.organization_enrollment_requests.rejected_utc IS
'Terminal rejected pilot request, not independently signed human or WORM evidence.';
