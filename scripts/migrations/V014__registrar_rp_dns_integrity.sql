-- V014: forward-only strict RP hostname hardening for V013; DO NOT rewrite V013.
-- Reject literal IPv4 addresses, numeric-only final DNS labels, and labels >63
-- characters. This is a PostgreSQL integrity guard, NOT proof of WebAuthn
-- credential attestation or approved human registration. No new privilege grants.

CREATE FUNCTION public.is_strict_reviewer_registration_dns_name(candidate text)
RETURNS boolean
LANGUAGE plpgsql IMMUTABLE STRICT
SET search_path=pg_catalog,pg_temp AS $$
DECLARE
    labels text[];
    part text;
BEGIN
    IF char_length(candidate) NOT BETWEEN 4 AND 253 OR
       candidate !~ '^[a-z0-9]+(-[a-z0-9]+)*(\.[a-z0-9]+(-[a-z0-9]+)*)+$'
    THEN
        RETURN false;
    END IF;
    labels := string_to_array(candidate,'.');
    IF coalesce(array_length(labels,1),0) < 2 OR
       labels[array_length(labels,1)] !~ '[a-z]'
    THEN
        RETURN false;
    END IF;
    FOREACH part IN ARRAY labels LOOP
        IF char_length(part)>63 THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END;
$$;
REVOKE ALL ON FUNCTION public.is_strict_reviewer_registration_dns_name(text)
    FROM PUBLIC;

-- Existing policies must also comply: migration aborts rather than allowing
-- a dangerous or ambiguous hostname to survive. Only schema owner may insert.
ALTER TABLE public.reviewer_registration_rp_policies
    ADD CONSTRAINT ck_registrar_rp_strict_dns_name_v014
        CHECK (public.is_strict_reviewer_registration_dns_name(rp_id));
COMMENT ON FUNCTION public.is_strict_reviewer_registration_dns_name(text) IS
'Owner-pinned reviewer WebAuthn registration DNS integrity helper; NOT an approved credential or attestation verifier.';
