-- V005: complete restricted role execution boundary for tenancy integrity triggers.
-- V003 created triggers as SECURITY INVOKER. This caused a restricted provisioning
-- credential to fail when triggered membership parent-row updates ran under that login.
-- Trigger code is reviewed, uses fixed pg_catalog,pg_temp search_path and fully
-- qualified public tables; only migration owner may alter it.
ALTER FUNCTION public.serialize_membership_mutation() SECURITY DEFINER;
ALTER FUNCTION public.assert_tenant_has_active_admin(uuid) SECURITY DEFINER;
ALTER FUNCTION public.check_admin_after_organization_change() SECURITY DEFINER;
ALTER FUNCTION public.check_admin_after_membership_change() SECURITY DEFINER;

-- Avoid direct use of invariant helpers to probe membership/organization existence.
REVOKE ALL ON FUNCTION public.assert_tenant_has_active_admin(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.serialize_membership_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.check_admin_after_organization_change() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.check_admin_after_membership_change() FROM PUBLIC;
