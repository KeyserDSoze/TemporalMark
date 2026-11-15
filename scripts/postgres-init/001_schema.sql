-- Application registry baseline. Run through a controlled migration mechanism in production.
CREATE TABLE IF NOT EXISTS organizations (
    id uuid PRIMARY KEY,
    display_name text NOT NULL CHECK (length(trim(display_name)) > 0),
    is_active boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS organization_memberships (
    organization_id uuid NOT NULL REFERENCES organizations(id),
    subject_id text NOT NULL CHECK (length(trim(subject_id)) > 0),
    role text NOT NULL CHECK (role IN ('tenant_admin', 'tenant_auditor', 'tenant_member')),
    is_active boolean NOT NULL DEFAULT true,
    PRIMARY KEY (organization_id, subject_id)
);
CREATE INDEX IF NOT EXISTS ix_memberships_active_admin
    ON organization_memberships (organization_id) WHERE role = 'tenant_admin' AND is_active;

-- Ensures last-admin removal/demotion is blocked even under competing transactions.
CREATE OR REPLACE FUNCTION protect_last_active_tenant_admin()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.is_active AND OLD.role = 'tenant_admin' AND
       (TG_OP = 'DELETE' OR NOT NEW.is_active OR NEW.role <> 'tenant_admin') THEN
        PERFORM pg_advisory_xact_lock(hashtext(OLD.organization_id::text));
        IF NOT EXISTS (
            SELECT 1 FROM organization_memberships
             WHERE organization_id = OLD.organization_id
               AND subject_id <> OLD.subject_id
               AND role = 'tenant_admin' AND is_active
        ) THEN
            RAISE EXCEPTION 'Each organization must retain an active tenant administrator';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_protect_last_admin ON organization_memberships;
CREATE TRIGGER trg_protect_last_admin
BEFORE DELETE OR UPDATE OF role, is_active ON organization_memberships
FOR EACH ROW EXECUTE FUNCTION protect_last_active_tenant_admin();

CREATE TABLE IF NOT EXISTS timestamp_registry (
    id uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id),
    issued_utc timestamptz NOT NULL,
    hash_algorithm_oid text NOT NULL,
    digest_base64 text NOT NULL,
    policy_oid text NOT NULL,
    provider_id text NOT NULL,
    token_sha256_hex char(64) NOT NULL,
    validation_state smallint NOT NULL CHECK (validation_state BETWEEN 0 AND 4),
    response_der bytea NOT NULL CHECK (octet_length(response_der) > 0),
    evidence_reference text,
    created_at_utc timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_timestamp_tenant_date
    ON timestamp_registry (organization_id, issued_utc, id);

-- No delete API exists. Database admin rights must be independently restricted in production.
