# OIDC Authentication 1.0.0

First stable release. Engine-side OpenID Connect sign-in for the OIE web
administrator: the plugin validates ID tokens itself, optionally provisions
engine users on first sign-in, binds every account permanently to
`issuer#subject`, and maps IdP claims to roles in the RBAC extension — so the
engine's audit log names real people rather than a shared service account.

**Everything is configured here.** This extension runs the whole Authorization
Code + PKCE flow — the provider redirect, the code exchange with the client
secret, token validation — and hands the web administrator a one-time ticket to
sign in with. The web administrator keeps no OIDC configuration. Register one
redirect URI at your provider: `<web-administrator-url>/oidc/callback`.

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

## Sign-in flow

The engine requires `X-Requested-With` on every API request, so the provider's
redirect cannot land on an engine endpoint. The web administrator's login card
therefore posts `/extensions/oidcauth/start` (the engine seals the attempt in an
HttpOnly cookie and returns the provider URL), the provider sends the browser to
`<web-administrator-url>/oidc/callback` — a route of the web app — and the card
posts the returned `code` and `state` to `/extensions/oidcauth/callback`. The
engine checks the state, exchanges the code with the secret and the PKCE
verifier, validates the ID token including its nonce, and answers with a
one-time ticket that the card redeems through the ordinary `/users/_login`, so
the session, the login audit event, and any second factor are exactly what a
password sign-in gets.

## Settings tab

- Client secret and web administrator URL are policy keys. The secret is never
  echoed: the tab shows a mask, and saving the mask keeps the stored value.
- Default role and every claim-to-role mapping target are chosen from the
  engine's RBAC roles; a stored name RBAC no longer lists stays selected and is
  marked rather than silently replaced. Linked accounts pick the engine user
  from a list, and once a sign-in has fetched discovery the `issuer#` half of a
  new binding is prefilled from the engine's own record of the issuer. All of
  these fall back to free text when the lists cannot be read.
- Claim fields suggest the usual names as you type (standard OpenID claims;
  for the roles claim the provider-specific paths, with your client ID filled
  in) and stay free text.
- **Test connection** is a pure check: it verifies discovery and counts the
  signing keys that could verify a token, and changes nothing.
- Fixed: choosing **Save** in the unsaved-changes prompt silently discarded the
  tab's changes while reporting success.
- A save is audited as **Manage OIDC configuration** with the user and outcome
  only; the policy body, client secret included, is excluded from the event.

## Known limitations

No RP-initiated or front-channel logout; confidential client only; one identity
provider per engine; one role per user; replay protection is per-JVM (window
bounded by `max-token-age-seconds`); deprovisioning takes effect at next
sign-in. See the README's *Limitations* section for what each means in practice.

## Verification

119 unit tests — including the engine-run flow against a local provider that
checks the secret, the PKCE verifier, the redirect URI, and the nonce — and this
build walked end to end on OIE 4.6.0 with RBAC 1.1.2 against Keycloak through
the engine-hosted flow (start, provider, `/oidc/callback`, ticket redemption): the settings tab rendered from the schema, refused a save
with no default role, verified discovery plus one reachable signing key on
**Test connection**, persisted, and the engine logged the policy as ACTIVE;
a first SSO sign-in JIT-provisioned the user with the IdP's email and name and
assigned the default role, which the engine then enforced (`manageOIDC`, role
management, and server settings all answered 403 to that user); a second sign-in
found the same account by its binding rather than creating another.
