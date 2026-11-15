-- V016 — DB-INTERNAL registrar insertion interlock for mistaken manual GRANT.
-- Forward-only: V001–V015 remain byte-for-byte/checksum unchanged.
--
-- V015 revoked the previously inherited NOLOGIN registrar EXECUTE privilege.
-- However a migration owner could accidentally GRANT EXECUTE on V013 directly
-- to a registrar LOGIN. Without this trigger, that stolen LOGIN could still
-- issue a forged UNCONSUMABLE nonce by bypassing the .NET OIDC gate.
--
-- Defense-in-depth: only a directly authenticated migration/function owner
-- may INSERT into the legacy intent table, including when a SECURITY
-- DEFINER function or a direct accidental grant attempts the INSERT.
-- This does not authenticate a real human WebAuthn registrar or verify a
-- signature, and schema owners/superusers can replace/drop the trigger.

CREATE FUNCTION public.block_nonowner_reviewer_registration_intent_insert()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- session_user is the original DB session principal, unchanged by
    -- outer SECURITY DEFINER calls; current_user here is this trigger
    -- function's independently privileged migration owner.
    -- SET ROLE does not change session_user. Superusers/schema owners
    -- remain inherently trusted and can alter authorization controls.
    IF session_user <> current_user THEN
        RAISE EXCEPTION
            'V016 security interlock: legacy unconsumable reviewer registration intents are owner-only'
            USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.block_nonowner_reviewer_registration_intent_insert()
    FROM PUBLIC;

CREATE TRIGGER trg_reviewer_registration_intents_owner_only_v016
BEFORE INSERT ON public.reviewer_registration_intents
FOR EACH ROW EXECUTE FUNCTION
    public.block_nonowner_reviewer_registration_intent_insert();

COMMENT ON FUNCTION public.block_nonowner_reviewer_registration_intent_insert() IS
'V016 DB-internal interlock: deny forged legacy nonce insert by nonowner session, including direct V013 EXECUTE regrant. NOT registered WebAuthn identity, human signing consent, WORM or QTSP.';

COMMENT ON TRIGGER trg_reviewer_registration_intents_owner_only_v016
ON public.reviewer_registration_intents IS
'Owner-only legacy diagnostic insert: an untrusted registrar SQL LOGIN may not mint a nonce even after mistaken direct EXECUTE GRANT. New signed release requires a distinct approved protocol (#50/#44).';
