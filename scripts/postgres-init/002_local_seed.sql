-- DEVELOPMENT FIXTURE ONLY; matches the Keycloak import user ID and organization claim.
INSERT INTO organizations (id, display_name)
VALUES ('11111111-1111-1111-1111-111111111111', 'Demo Organization')
ON CONFLICT (id) DO NOTHING;

INSERT INTO organization_memberships (organization_id, subject_id, role, is_active)
VALUES ('11111111-1111-1111-1111-111111111111',
        '00000000-0000-0000-0000-000000000001', 'tenant_admin', true)
ON CONFLICT (organization_id, subject_id) DO NOTHING;
