-- V018 — privacy-minimized audit for authorized SHA-256 imprint search.
-- Forward-only: V001–V017 must remain byte-for-byte unchanged.
-- Records tenant, actor, action and occurrence only. No searched document
-- imprint, match count, result flag, receipt identifier or query bounds.
-- Existing runtime INSERT/SELECT grants and append-only trigger are retained.
-- This PostgreSQL pilot table is NOT independently sealed, WORM or qualified.
ALTER TABLE public.tenant_audit_events
    DROP CONSTRAINT tenant_audit_events_action_check;
ALTER TABLE public.tenant_audit_events
    ADD CONSTRAINT tenant_audit_events_action_check
    CHECK (action IN (
        'period_export_prepared',
        'receipt_download_prepared',
        'document_imprint_search_performed'
    ));

ALTER TABLE public.tenant_audit_events
    DROP CONSTRAINT chk_audit_payload;
ALTER TABLE public.tenant_audit_events
    ADD CONSTRAINT chk_audit_payload CHECK (
        (action = 'period_export_prepared' AND receipt_id IS NULL AND
         period_from_utc IS NOT NULL AND period_to_utc_exclusive IS NOT NULL AND
         period_from_utc < period_to_utc_exclusive)
        OR
        (action = 'receipt_download_prepared' AND receipt_id IS NOT NULL AND
         period_from_utc IS NULL AND period_to_utc_exclusive IS NULL)
        OR
        (action = 'document_imprint_search_performed' AND receipt_id IS NULL AND
         period_from_utc IS NULL AND period_to_utc_exclusive IS NULL)
    );
