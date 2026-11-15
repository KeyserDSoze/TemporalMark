-- V015 — FAIL-CLOSED release interlock for UNSIGNED registrar intent issuance.
-- V001–V014 checksums remain immutable. A dedicated stolen registrar LOGIN
-- may call V013 directly without any verified current IdP, WebAuthn key or
-- independent human signature. V013 creates only an UNCONSUMABLE nonce, not
-- a credential or tenant approval, but MUST NOT remain an executable entry
-- point for future trusted WebAuthn registration until an independently
-- signed, transaction-bound database release path is reviewed (#50/#44).
--
-- A migration/schema owner retains privileged diagnostic rights: that is
-- NOT independently authenticated registrar consent, WORM or QTSP evidence.
-- Do not seed a new registrar LOGIN, membership, key, certificate or signer.
REVOKE EXECUTE ON FUNCTION
    public.issue_reviewer_registration_intent(text,text,text,text,text)
    FROM temporalmark_credential_registrar_group;

-- Retain the existing deny-by-default posture of other application users,
-- including PUBLIC's default EXECUTE inheritance from new functions.
REVOKE EXECUTE ON FUNCTION
    public.issue_reviewer_registration_intent(text,text,text,text,text)
    FROM PUBLIC, temporalmark_approver_group,
         temporalmark_provisioner_group, temporalmark_runtime_group;

-- If an environment was manually over-granted, migration must abort rather
-- than silently advertise that the security interlock is active.
DO $$
BEGIN
    IF has_function_privilege(
        'temporalmark_credential_registrar_group',
        'public.issue_reviewer_registration_intent(text,text,text,text,text)',
        'EXECUTE'
    ) OR has_function_privilege(
        'temporalmark_approver_group',
        'public.issue_reviewer_registration_intent(text,text,text,text,text)',
        'EXECUTE'
    ) OR has_function_privilege(
        'temporalmark_provisioner_group',
        'public.issue_reviewer_registration_intent(text,text,text,text,text)',
        'EXECUTE'
    ) OR has_function_privilege(
        'temporalmark_runtime_group',
        'public.issue_reviewer_registration_intent(text,text,text,text,text)',
        'EXECUTE'
    ) THEN
        RAISE EXCEPTION
            'V015 registrar issuance interlock failed: app role still has V013 EXECUTE'
            USING ERRCODE='42501';
    END IF;
END
$$;

COMMENT ON FUNCTION public.issue_reviewer_registration_intent(
    text,text,text,text,text) IS
'SECURITY INTERLOCK V015: owner-only LEGACY UNTRUSTED unconsumable nonce diagnostic. Registrar NOLOGIN group EXECUTE revoked. DO NOT REGRANT until a versioned, verified cryptographic one-time registration protocol exists (#50/#44). No WebAuthn key, human signing consent, WORM or legal QTSP qualification.';
