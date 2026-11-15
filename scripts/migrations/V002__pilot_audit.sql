-- Development schema. A production audit record requires WORM/sealing outside PostgreSQL.
CREATE TABLE IF NOT EXISTS tenant_audit_events (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    actor_subject_id text NOT NULL
        CHECK (char_length(actor_subject_id) BETWEEN 1 AND 255 AND
               actor_subject_id = btrim(actor_subject_id) AND
               actor_subject_id !~ '[[:cntrl:]]'),
    action text NOT NULL CHECK (action IN ('period_export_prepared', 'receipt_download_prepared')),
    occurred_utc timestamptz NOT NULL,
    receipt_id uuid,
    period_from_utc timestamptz,
    period_to_utc_exclusive timestamptz,
    CONSTRAINT chk_audit_payload CHECK (
       (action = 'period_export_prepared' AND receipt_id IS NULL AND
        period_from_utc IS NOT NULL AND period_to_utc_exclusive IS NOT NULL AND
        period_from_utc < period_to_utc_exclusive)
       OR
       (action = 'receipt_download_prepared' AND receipt_id IS NOT NULL AND
        period_from_utc IS NULL AND period_to_utc_exclusive IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS ix_tenant_audit_timeline
    ON tenant_audit_events (organization_id, occurred_utc DESC, id DESC);

-- Defence in depth against accidental UPDATE/DELETE. A database owner can alter schema;
-- it is NOT certified immutability, and production must remove table-owner privileges.
CREATE OR REPLACE FUNCTION reject_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Tenant audit history may only be appended';
END;
$$;
DROP TRIGGER IF EXISTS trg_reject_audit_mutation ON tenant_audit_events;
CREATE TRIGGER trg_reject_audit_mutation
BEFORE UPDATE OR DELETE ON tenant_audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
