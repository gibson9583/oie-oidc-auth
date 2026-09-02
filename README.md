# OIE OIDC Authentication

Engine-side authorization extension for the OIE web administrator's native OpenID Connect login. It validates signed ID tokens itself, creates real named engine users when configured, permanently binds each account to `issuer#subject`, and optionally maps provider groups to the RBAC extension. Local password login is untouched.

## Install and configure

Build with Java 17 and an OIE 4.6.0 installation:

```sh
OIE_HOME=/path/to/oie mvn clean package
```

Extract `target/oidcauth-1.0.0.zip` into the engine extensions directory and restart. Verify the extension loaded before touching the UI: the engine log must contain one `OIDC authentication is …` line saying which state it is in — `ACTIVE for <discovery-url>`, `disabled (policy key 'enabled' is false)`, `SWITCHED OFF by OIE_OIDC_DISABLED`, or `not configured: <reason>`. No such line means the extension did not load at all, and no endpoint, permission, or settings tab exists.

Permissions with RBAC installed: users on the **admin role** (`is_admin`) hold `manageOIDC` — like every extension permission — automatically and implicitly. Do **not** try to tick it on the admin role; that role is deliberately read-only in the role editor because its holders bypass stored permissions. Grant `manageOIDC` only to non-admin roles that should manage SSO policy. Without RBAC the panel is available to any signed-in user. The web module decides whether to register the tab by probing `GET /api/extensions/oidcauth/configuration` — the same `manageOIDC`-gated endpoint the panel uses — during registration: a 403 hides the tab, and anything else shows it. So if the tab is missing, check that endpoint's response rather than RBAC's permission list. The gate is presentation only; the servlet authorizes every operation independently.

Configure under **Settings → OIDC Authentication**: tick **Enable OIDC login** to unlock the fields, then use **Save**, **Refresh**, and **Test connection** in the tab's task pane. Save validates the policy first, persists it to the **engine database** (the engine's native per-plugin properties, so it rides normal database backups), and reloads the live plugin — no engine restart. Test connection verifies discovery and JWKS reachability for the values currently on the form.

The plugin follows the engine's native settings lifecycle: defaults are seeded into the store on first install (and newly added keys are merged on upgrade), the engine pushes the stored policy into the plugin at startup, and saves persist and apply in one step — the plugin never reads the property store at request time. Automated installs provision entirely through `OIE_OIDC_*` environment variables (or system properties); there is no config file.

The extension exposes only enabled state, discovery URL, and client ID from its narrow pre-auth `/api/extensions/oidcauth/public` endpoint. The Node web tier uses that metadata to decide whether to advertise SSO and to perform authorization-code exchange. The client secret remains only in web deployment configuration; it is never stored by or returned from the engine.

Every property can be overridden with an `OIE_OIDC_*` environment variable (dots and hyphens become underscores) or `org.openintegrationengine.oidc.*` system property; overrides win over the stored (UI-managed) policy, so operators can pin values the form cannot change. `OIE_OIDC_DISABLED=true` is the emergency kill switch and needs neither the database nor the UI.

`roles.claim` accepts a dotted path into nested claims, not just a top-level name — Keycloak puts realm roles at `realm_access.roles` and client roles at `resource_access.<client-id>.roles`, and only group membership is flat. A claim whose literal name contains dots is still matched first, so existing configurations keep their meaning. Whichever claim you choose, its Keycloak mapper needs **Add to ID token** switched on: this extension validates the ID token, while Keycloak's role mappers default to the access token only — a mismatch that looks exactly like "roles are being ignored".

> **Without RBAC, JIT-provisioned users are fully privileged.** The engine has no
> permission model of its own — authorization comes entirely from the
> role-based-access-control extension — so with RBAC absent every account the
> engine holds can do everything. Turning on `jit.enabled` without RBAC installed
> therefore means anyone your IdP will issue a token for becomes a full
> administrator on first sign-in, with no further approval step. This extension
> does not refuse that configuration and offers no setting to soften it: if you
> enable JIT provisioning, install RBAC first, or restrict at the IdP which users
> may receive a token for this client. With RBAC installed, `roles.default` is
> mandatory and bounds what a newly provisioned user gets.

Existing users are rejected unless their exact `issuer#subject` is present in `linked-accounts`. New JIT users receive the binding automatically. `jit.enabled` defaults to **off** — an absent key never means "provision users". `roles.map` and `linked-accounts` use comma-separated `key=value` entries (the settings panel renders them as row editors). Role resolution per login: first explicit `roles.map` hit in claim order, then — with `roles.infer` enabled — the first claim value exactly matching an existing RBAC role name, then `roles.default`. Explicit mappings always beat inference, so the two compose: infer the bulk, map the exceptions. Leave `roles.infer` off unless the claim is curated (a dedicated client-role mapper): any matching value, including `Administrator`, grants that role. RBAC failures never block authentication, and the extension will not demote the last administrator.

`roles.default` is **required** whenever OIDC is enabled and RBAC is installed, unless `roles.sync=never` (which stops this extension touching roles at all). Without a default, a returning user whose claims match nothing keeps whatever role they already had, so removing their group at the IdP would not remove their engine access; requiring one keeps claims always resolving to something. Note the check is that a value is *set*, not that it names a role that exists — a typo'd or renamed role logs `OIDC role '…' does not exist; leaving role unchanged` at login and leaves the previous role in place, so verify the value matches a real RBAC role.

**Upgrade note.** An existing OIDC+RBAC policy with no `roles.default` is rejected on load, and the symptom is quiet: the engine still starts, but the policy does not apply. `/public` then reports `configured:false`, so the web administrator stops offering the SSO button; and a sign-in attempt that does reach the engine is told "SSO is disabled on this engine". The settings tab still shows **Enable OIDC login** ticked — it serves the stored properties, which is what you need to see in order to fix them — but banners the real reason above the form, and the engine log carries the same text as `OIDC authentication is not configured: roles.default is required …`. Local password login is unaffected, so a local administrator can always fix it in the tab — but an SSO-only deployment whose administrators were all JIT-provisioned has no password to fall back on, and must use the environment override `OIE_OIDC_ROLES_DEFAULT=<role>`, which applies before validation and needs neither the database nor the UI.

The web administrator redirect URI is `<web-origin>/oidc/callback`. RP-initiated and front-channel logout are not implemented. Keep the engine API session timeout aligned with the provider's session policy.

**Replay protection is per-JVM.** A presented ID token is remembered so it cannot be used twice, but that memory lives in the engine process: it is lost on restart, and it is not shared between nodes. So a captured token can be replayed once per node, and once more after a restart, within `max-token-age-seconds` (default 300) of its issuance — after which it is refused as expired regardless. The web tier's `nonce` check is what prevents replay in the ordinary browser flow; this cache is the engine-side backstop for a token captured in transit. A shared cache is deliberately out of scope for 1.0. Lowering `max-token-age-seconds` narrows the window.

## Policy keys

Every key lives in the engine database and is edited under **Settings → OIDC Authentication**. Any of them can be pinned by an environment variable or a system property, which overlay the stored value at load time and are never written back — see *Operator overrides* below. `oidc.properties.example` is a copy of this table in properties form; it is a reference only and is never read by the plugin.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Master switch for this engine's OIDC policy. |
| `discovery-url` | — | The provider's `.well-known/openid-configuration`. Required when enabled. HTTPS, except for localhost. |
| `client-id` | — | The client this engine expects tokens to be issued for; checked against `aud`. Required when enabled. |
| `username-claim` | `preferred_username` | Which claim becomes the engine username. |
| `username-prefix` | *(empty)* | Prepended to the normalized username. Must match `a-z 0-9 . _ @ + : -`. |
| `allowed-algorithms` | `RS256,RS384,RS512,ES256,ES384,ES512` | Signature algorithms accepted. Symmetric (`HS*`) is never accepted. |
| `clock-skew-seconds` | `60` | Tolerance for `exp`/`nbf` against local time. |
| `max-token-age-seconds` | `300` | Oldest `iat` accepted, and the lifetime of a replay-cache entry. |
| `jwks-cache-ttl-seconds` | `300` | How long the discovery document and key set are reused before refetching. |
| `jit.enabled` | `false` | Create an engine user on first sign-in. **Read the JIT warning above before enabling.** |
| `jit.email-claim` | `email` | Claim copied to the user's email, at creation and on re-login. |
| `jit.name-claim` | `name` | Claim split into first/last name. |
| `jit.organization-claim` | `organization` | Claim copied to the user's organization. |
| `linked-accounts` | *(empty)* | `engine-user=issuer#subject`, comma-separated. The only way a **pre-existing** account may be claimed by SSO. |
| `roles.claim` | `groups` | Claim carrying role values. A dotted path descends into nested claims (`realm_access.roles`). A scalar value is split on commas, or on whitespace if it contains none. |
| `roles.map` | *(empty)* | `claim-value=RBAC role`, comma-separated, first match in claim order wins. |
| `roles.default` | *(empty)* | Role for a user whose claims match nothing. **Required** when enabled with RBAC installed, unless `roles.sync=never`. |
| `roles.sync` | `always` | `always` — reconcile the role on every login; `jit-only` — only when the account is created; `never` — this extension never touches roles. |
| `roles.infer` | `false` | Also accept a claim value that exactly matches an existing RBAC role name. Off by default because any matching value, including `Administrator`, then grants that role. |

### Operator overrides

Each key above may be pinned outside the database, which is how automated deployments provision SSO:

- Environment: `OIE_OIDC_<KEY>`, uppercased with dots and hyphens folded to underscores — `roles.default` → `OIE_OIDC_ROLES_DEFAULT`, `jwks-cache-ttl-seconds` → `OIE_OIDC_JWKS_CACHE_TTL_SECONDS`.
- System property: `org.openintegrationengine.oidc.<key>`, verbatim — `-Dorg.openintegrationengine.oidc.roles.default=User`.

The environment wins over a system property, and both win over the stored policy. Pinned keys are shown read-only in the settings tab and excluded from a save, so editing one cannot quietly write the pin's value into the database.

**`OIE_OIDC_DISABLED` is a separate emergency switch, not a policy key.** Setting it to `true` refuses every OIDC sign-in and stops the login screen advertising SSO, whatever the stored policy says, and it needs neither the database nor the UI. Note the polarity is the opposite of `OIE_OIDC_ENABLED`: `OIE_OIDC_DISABLED=true` and `OIE_OIDC_ENABLED=false` both switch SSO off, but the first is an override that leaves the policy intact and reports itself in the settings tab, while the second pins the policy key.

## Limitations

Deliberate for 1.0, listed so they are not discovered during an incident:

- **RP-initiated and front-channel logout are not implemented.** Signing out of the engine does not end the provider session. Align the engine's `server.api.sessionmaxinactiveinterval` with the provider's session policy, or a closed engine session can be re-established silently from a still-live IdP session.
- **Confidential client only.** The web tier holds the client secret and performs the code exchange server-side; PKCE public-client mode is not offered. SSO therefore requires the web administrator's Node deployment — the WAR has no server half.
- **One identity provider per engine.** The engine loads exactly one `AuthorizationPlugin`, so a second provider cannot be added alongside this one. This is an engine ceiling, not a plugin limit.
- **One role per user.** RBAC's own model; `roles.map` is first-match-wins in claim order, so a user in several mapped groups gets the first, not a union.
- **Replay protection is per-JVM** — see above.
- **A local password that literally begins `oidc:` is routed to the SSO path** and will fail there rather than being checked against the local credential. Self-inflicted and vanishingly unlikely, but it is a real way to lock an account out of local login.
- **Deprovisioning is login-time only.** Removing a user at the IdP blocks their next sign-in; it does not disable or delete the engine account, and nothing sweeps for accounts whose IdP identity has gone. Remove the engine user as well.
