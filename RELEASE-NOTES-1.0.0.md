# OIDC Authentication 1.0.0

First stable release. Engine-side OpenID Connect sign-in for the OIE web
administrator: the plugin validates ID tokens itself, optionally provisions
engine users on first sign-in, binds every account permanently to
`issuer#subject`, and maps IdP claims to roles in the RBAC extension — so the
engine's audit log names real people rather than a shared service account.

**Requires both halves.** This extension owns identity on the engine; the
browser-facing Authorization Code + PKCE flow runs in the web administrator's
Node deployment, which holds the client secret. The WAR has no server half and
never offers SSO. Register one redirect URI at your provider:
`<web-administrator-origin>/oidc/callback`.

## Upgrading from 0.1.0

Two changes alter behaviour on existing installations. Both fail closed, and
both are quiet if you are not expecting them.

**`jit.enabled` now defaults to off when the key is absent.** The parser
previously defaulted it *on* while the loader seeded it off, so a stored policy
missing the key silently provisioned users while the settings tab displayed the
feature as disabled. If you relied on that — and the tab said "No" — you must
now set it explicitly.

**`roles.default` is required when OIDC is enabled and RBAC is installed**,
unless `roles.sync=never`. A policy without it is rejected at load, and the
symptom is easy to misread: the engine still starts, but SSO stops being
advertised and the settings tab still shows *Enable OIDC login* ticked, because
it serves the stored policy rather than the parsed one. The real reason is in
the engine log. If an SSO-only deployment locks itself out this way, set
`OIE_OIDC_ROLES_DEFAULT=<role>` — it applies before validation and needs neither
the database nor the UI.

## Fixed

- A profile refresh on re-login ran **before** the subject-binding checks, so
  anyone the IdP would issue a token for could claim `preferred_username=admin`
  and overwrite the real administrator's name, email and organization — on a
  login the engine then refused. It now runs only after the account is proven.
- An IdP username change created a **second** engine account bound to the same
  subject, orphaning the first, which stayed bound and would become loginable
  again if the old name were reissued. The account now follows the IdP, and a
  rename into a name someone else holds is refused rather than merged.
- A returning user whose claims resolved to no role **kept the role they already
  had**, so revoking their IdP group did not revoke their engine access.
- A scalar role claim (`"groups": "admins,auditors"`) was taken as one
  unmatchable value, so the entire mapping silently did nothing.
- `OIE_OIDC_DISABLED` was honoured per login but not by the pre-auth probe, so
  the login screen kept advertising SSO while every attempt was refused.
- A policy the engine **rejected** displayed as healthy in the settings tab. The
  tab now reports the rejection, the kill switch, the redirect URI, and which
  keys an operator has pinned — pinned keys are shown read-only and excluded
  from saves, so editing one can no longer write the pin into stored policy.
- Half-filled claim-mapping rows were dropped on save behind a success toast,
  producing a policy the engine never received. Rows are now validated, and
  `=` is accepted in values, which `linked-accounts` subjects require.
- The settings tab was invisible to a role granted only `manageOIDC`.
- **Test connection** verified discovery only. It now fetches the key set and
  counts keys that could actually verify a token, so a provider with
  unreachable or encryption-only keys no longer tests green.
- An `Error` raised while resolving the user controller escaped `authorizeUser`
  instead of failing closed.

## Known limitations

No RP-initiated or front-channel logout; confidential client only; one identity
provider per engine; one role per user; replay protection is per-JVM (window
bounded by `max-token-age-seconds`); deprovisioning takes effect at next
sign-in. See the README's *Limitations* section for what each means in practice.

## Verification

83 unit tests. **Not yet exercised on a live engine** — install the zip on a
clean OIE 4.6.0 and walk the settings tab and one SSO sign-in before relying on
this build.
