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

## Hardening after security review

- Only a ticket is a login credential. A bare ID token presented to
  `/users/_login` — the pre-1.0 shape — is refused without being examined; it
  was the one route on which the nonce was never checked.
- An account bound to a provider subject refuses a local password while SSO is
  active, unless the operator listed it in `linked-accounts`. Before, anyone
  who could set an engine password on a JIT-created account (the user, through
  their own profile) kept a way in after the provider removed them.
- The login throttle keyed on the username hint, which the web client always
  sends as `oidc`: twenty SSO sign-ins a minute per engine, and twenty
  anonymous POSTs denied everyone for the next minute. Ticket redemption is a
  single map lookup on a 256-bit id and is no longer throttled. The callback —
  the step that costs an outbound token exchange — is throttled per client
  (first `X-Forwarded-For` hop, which the web administrator's proxy sets and the
  engine already trusts for audit) and in total, instead of per proxy address.
- The JWKS fetch ran on nimbus's defaults: 500 ms to connect and read, a 50 KB
  body. It now has the same bounds as discovery (10 s, 1 MiB) and refetches an
  unknown key id at most every 30 seconds.
- The code exchange authenticates with `client_secret_basic`, the method every
  provider must support (Cognito accepts nothing else), falling back to
  `client_secret_post` only when discovery says that is all the provider takes.
- A spent token is remembered for `max-token-age-seconds` plus the clock skew,
  the whole window in which it would still validate; the last skew seconds of
  a token's life were replayable.
- `/public` no longer reports the discovery URL and client ID; the return path
  is capped at 2 KB so the sealed cookie stays deliverable; **Test connection**
  is audited (without its body); discovery refreshes no longer hold every
  concurrent sign-in behind one fetch.
- The client secret is encrypted with the engine's key before it is stored.
  The Extensions page's raw **Properties** view and server-configuration
  exports show ciphertext; a secret stored in the clear, or one another
  engine's key cannot decrypt, is refused at load until it is entered again.
  The engine's generic plugin-properties endpoints carry no permission of
  their own; the role-based-access-control extension gates them by
  `manageExtensions` from its next release, and refuses names that are not
  installed extensions.
- Web administrator: sign-out with auto-redirect on shows the sign-in card
  instead of bouncing straight back to the provider, and a crafted
  `/oidc/callback?error=` link no longer evicts a signed-in user.

## Known limitations

No RP-initiated or front-channel logout; confidential client only; one identity
provider per engine; one role per user; replay protection is per-JVM (window
bounded by `max-token-age-seconds`); deprovisioning takes effect at next
sign-in. See the README's *Limitations* section for what each means in practice.

## Verification

130 unit tests — including the engine-run flow against a local provider that
checks the secret, the PKCE verifier, the redirect URI, and the nonce — and this
build walked end to end on OIE 4.6.0 with RBAC 1.1.2 against Keycloak through
the engine-hosted flow (start, provider, `/oidc/callback`, ticket redemption): the settings tab rendered from the schema, refused a save
with no default role, verified discovery plus one reachable signing key on
**Test connection**, persisted, and the engine logged the policy as ACTIVE;
a first SSO sign-in JIT-provisioned the user with the IdP's email and name and
assigned the default role, which the engine then enforced (`manageOIDC`, role
management, and server settings all answered 403 to that user); a second sign-in
found the same account by its binding rather than creating another.
