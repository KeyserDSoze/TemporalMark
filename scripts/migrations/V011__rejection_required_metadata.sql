-- V011 — Explicit rejection metadata completeness.
-- PostgreSQL CHECK considers UNKNOWN (NULL) as satisfied, so nullable regex
-- or IN expressions in V010 must be complemented with explicit IS NOT NULL.
-- Historical migrations V001–V010 are immutable; never rewrite them.
ALTER TABLE public.organization_enrollment_requests
    ADD CONSTRAINT ck_terminal_rejection_mandatory_fields_v011 CHECK (
        rejected_utc IS NULL OR (
            rejected_by_subject IS NOT NULL AND
            rejection_proof_sha256 IS NOT NULL AND
            rejection_review_sha256 IS NOT NULL AND
            rejection_reason_code IS NOT NULL
        )
    );
COMMENT ON CONSTRAINT ck_terminal_rejection_mandatory_fields_v011
ON public.organization_enrollment_requests IS
'Reject terminal rows with NULL proof hash, original-scope digest or decision reason; do not rely on UNKNOWN in a SQL CHECK.';
