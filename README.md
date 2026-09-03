# OIE OIDC Authentication

This extension adds OpenID Connect single sign-on to the OIE web administrator. It runs on the engine. It sends the browser to the identity provider and exchanges the authorization code. It validates the ID token and signs the user in as a named engine user. It can create engine users on first sign-in, and it can assign RBAC roles from provider claims.

**Documentation:** the [wiki](https://github.com/gibson9583/oie-oidc-auth/wiki) has installation and configuration walkthroughs with screenshots, provider guides for Keycloak, Microsoft Entra ID, Okta, and AWS Cognito, and a troubleshooting page. This README is the reference.

## Requirements

- OIE 4.6.0.
- OIE web administrator 0.9.0 or newer.
- A confidential client at an OpenID Connect provider. You need its client ID and client secret.
- The redirect URI `<web-administrator-url>/oidc/callback`, registered at the provider.
- Optional: the role-based-access-control (RBAC) extension. Role assignment needs it. Read *Just-in-time users* before you enable user creation without it.

To build: Java 17, Maven, and an OIE 4.6.0 installation.

## Build

```sh
OIE_HOME=/path/to/oie mvn clean package
```

The build writes `target/oidcauth-1.0.0.zip`. Each release on GitHub also carries this file.

## Install

1. Extract the zip into the engine's extensions directory.
2. Restart the engine.
3. Find one line in the engine log that starts with `OIDC authentication is`. The line reports one of four states:
   - `ACTIVE for <discovery-url>`
   - `disabled (policy key 'enabled' is false)`
   - `SWITCHED OFF by OIE_OIDC_DISABLED`
   - `not configured: <reason>`

If the log has no such line, the extension did not load. The engine then has no OIDC endpoints, no `manageOIDC` permission, and no settings tab. The engine writes this line at startup and after each save.

## Permissions

The extension permission `manageOIDC` protects the settings tab and its API.

With RBAC installed:

- Users on the admin role (`is_admin`) hold `manageOIDC`. They hold every extension permission. Do not add `manageOIDC` to the admin role. The role editor shows that role read-only.
- Grant `manageOIDC` to each other role that must manage the SSO policy.

Without RBAC, every signed-in user can open the tab.

The web module sends `GET /api/extensions/oidcauth/configuration` when it loads. A `403` response hides the tab. Any other response shows the tab. If the tab is missing, check that response. The servlet checks the permission on every operation.

The engine's audit log records each save as **Manage OIDC configuration** and each test as **Test OIDC configuration**. Each event records the user and the outcome only. No event contains the policy or the client secret.

## Configure

1. Register the client at the provider with the redirect URI `<web-administrator-url>/oidc/callback`. The settings tab shows the exact value after you enter the web administrator URL.
2. In the web administrator, open **Settings → OIDC Authentication**.
3. Select **Enable OIDC login**. This unlocks the other fields.
4. Enter the **Discovery URL**, the **Client ID**, the **Client secret**, and the **Web administrator URL**.
5. Select **Test connection**. This reads the discovery document, fetches the key set, and counts the signing keys that can verify a token. It changes nothing.
6. Select **Save**.

**Save** validates the policy, stores it in the engine database, and applies it to the running extension. No restart is necessary. **Refresh** reads the stored policy again.

The tab has these properties:

- Every field stays locked until **Enable OIDC login** is selected.
- A field pinned by an operator override is read-only and marked *pinned*. See *Operator overrides*.
- A banner reports an active kill switch. A banner reports a policy the engine rejected, with the reason.
- **Default role** and each **Claim-to-role mappings** target offer the engine's RBAC roles. A stored name that RBAC no longer lists stays selected and is marked.
- **Linked accounts** offer the engine's users. After a sign-in has read the discovery document, the tab fills in the `issuer#` half of a new binding.
- The claim fields suggest common claim names as you type. They accept any text.
- Each list falls back to free text when the tab cannot read it.
- The tab shows a stored client secret as `********`. Saving the mask keeps the stored secret. Type a new value to replace it.

## Policy storage

The policy lives in the engine database as the extension's plugin properties. The client secret is encrypted with the engine's key before it is stored, so the raw properties view on the Extensions page and a server-configuration export show ciphertext. A secret stored in the clear, or one that another engine's key cannot decrypt, is refused until it is entered again in the settings tab. An export restored onto an engine with a different keystore therefore needs the secret entered again.

### Operator overrides

Each policy key can be pinned outside the database:

- Environment variable: `OIE_OIDC_<KEY>`. Write the key in upper case and replace each dot and hyphen with an underscore. `roles.default` becomes `OIE_OIDC_ROLES_DEFAULT`.
- System property: `org.openintegrationengine.oidc.<key>`, with the key unchanged. Example: `-Dorg.openintegrationengine.oidc.roles.default=User`.

An environment variable wins over a system property. Both win over the stored policy. The tab shows a pinned key read-only and does not include it in a save. Automated installations can set the whole policy this way.

### Kill switch

`OIE_OIDC_DISABLED=true` (or the system property `org.openintegrationengine.oidc.disabled=true`) switches SSO off. The engine refuses every OIDC sign-in, and the sign-in page stops offering SSO. The stored policy stays unchanged, and the tab reports the switch. This is different from `OIE_OIDC_ENABLED=false`, which pins the policy key `enabled`.

## Sign-in flow

The engine exposes three operations that need no session: `GET /api/extensions/oidcauth/public`, `POST /start`, and `POST /callback`. Every engine API request must carry the `X-Requested-With` header, so the provider never contacts the engine directly. The web administrator relays the provider's answer.

1. The sign-in page reads `/public`. The response carries `configured`, `providerLabel`, and `autoRedirect`, and nothing about the provider.
2. The user selects **Sign in with <label>**. The page posts `/start` with the route to return to. The engine seals the `state`, the `nonce`, the PKCE verifier, and the return route in the HttpOnly cookie `oie-oidc-txn`, which lasts ten minutes. The engine returns the provider's authorization URL, and the browser opens it.
3. The provider sends the browser to `<web-administrator-url>/oidc/callback` with `code` and `state`.
4. The page posts `code` and `state` to `/callback`. The engine opens the cookie, checks `state`, and exchanges the code with the client secret and the PKCE verifier. It validates the ID token, including the `nonce`. It returns a one-time ticket that lasts sixty seconds.
5. The page posts `password=oidc:ticket:<id>` to `/users/_login`. The engine validates the token again, resolves the engine user, and assigns the role. The session, the login audit event, and any second factor are the same as for a password sign-in.

Rules that apply to this flow:

- Only a ticket is a sign-in credential. The engine refuses an ID token sent to `/users/_login` directly.
- The return route must be a path on the web administrator of at most 2048 characters. Any other value returns the user to `/`.
- The code exchange uses `client_secret_basic`. It uses `client_secret_post` only when the provider's discovery document lists `client_secret_post` and not `client_secret_basic`.
- The engine limits `/callback` to sixty requests per minute per client and six hundred per minute in total. The client is the first `X-Forwarded-For` address when the header is present, and the peer address otherwise. `/public` and `/start` have no limit.
- After a refused attempt, the web administrator asks the provider for `prompt=login`, so the provider asks for credentials again.

### Token validation

- The discovery URL, the `jwks_uri`, the authorization endpoint, and the token endpoint must use HTTPS. Plain HTTP is accepted for `localhost` only.
- The engine keeps the discovery document for `jwks-cache-ttl-seconds`.
- The engine keeps the key set for `jwks-cache-ttl-seconds`. It fetches the key set with a ten-second timeout and a one-megabyte limit. An unknown key ID causes one new fetch at most every thirty seconds.
- The token algorithm must be in `allowed-algorithms`. The engine never accepts `HS*` or `none`.
- `iss` must equal the discovery document's issuer. `aud` must contain the client ID. A token with several audiences must carry `azp` equal to the client ID.
- `exp`, `nbf`, and `iat` are checked against the engine clock with `clock-skew-seconds` of tolerance. `iat` must be at most `max-token-age-seconds` old.
- The engine remembers each accepted token for `max-token-age-seconds` plus `clock-skew-seconds` and refuses it a second time. This memory lives in the engine process. A restart clears it, and engine nodes do not share it.

## Accounts

- The engine username is the `username-claim` value, normalized (NFKC), lower-cased, and prefixed with `username-prefix`. The result must match `a-z 0-9 . _ @ + : -` and be at most 128 characters.
- On first sign-in the engine binds the account to `issuer#subject` and stores the binding as the user preference `oidc.subject`.
- An existing account without a binding is refused, unless `linked-accounts` lists it with the exact `issuer#subject`.
- A sign-in whose `issuer#subject` differs from the account's binding is refused.
- When the provider changes a user's username, the bound account takes the new name. When the new name belongs to a different account, the sign-in is refused.
- When one `issuer#subject` is bound to two accounts, the sign-in is refused until an administrator resolves the duplicate.
- On each sign-in the engine copies the email, name, and organization claims to the account when they differ. The name claim is split at its last space into first name and last name.
- An SSO account has no first-login setup step. The engine clears the `firstlogin` preference on each sign-in.
- An account bound to a provider subject refuses a local password while SSO is active. The message is `This account signs in through SSO.` Accounts in `linked-accounts` keep their local password. When SSO is off (policy disabled, or the kill switch set), local passwords work for every account.
- A local password that starts with `oidc:` is treated as an SSO credential and is refused.

### Just-in-time users

`jit.enabled=true` creates an engine user on first sign-in. The account gets the email, name, and organization from the claims, the `issuer#subject` binding, and no engine password.

> **Without RBAC, every engine user holds full administrative access.** The engine has no permission model of its own. With `jit.enabled=true` and no RBAC extension, each person the provider issues a token for becomes a full administrator on first sign-in. The extension does not refuse this configuration. Install RBAC first, or restrict at the provider which users can receive a token for this client. With RBAC installed, `roles.default` is required and bounds what a new user can do.

## Roles

Role assignment needs the RBAC extension. The engine assigns one role per user.

`roles.claim` names the claim that carries the role values. A dotted path, such as `realm_access.roles`, descends into nested claims. The engine tries the exact top-level name first. A list claim gives one value per element. A text claim is split on commas, or on whitespace when it has no comma.

The engine resolves the role in this order:

1. The first `roles.map` entry whose key equals a claim value, in claim order.
2. With `roles.infer=true`, the first claim value that equals the name of an existing RBAC role.
3. `roles.default`.

Keep `roles.infer=false` unless the claim is curated. Any matching value, including `Administrator`, grants that role.

`roles.sync` controls when the engine assigns the role: `always` on every sign-in, `jit-only` when the account is created, `never` not at all.

`roles.default` is required when the policy is enabled, RBAC is installed, and `roles.sync` is not `never`. The check is that the key has a value, not that the role exists. When the resolved role does not exist, the engine logs `OIDC role '…' does not exist; leaving role unchanged` and keeps the current role.

The engine never demotes the last administrator. A failure in RBAC never blocks a sign-in.

The engine logs each role decision at DEBUG. Set the logger `org.openintegrationengine.plugins.oidc` to DEBUG in the engine's log4j2 configuration to see which claim was read and which values it carried.

### The roles claim must be in the ID token

The engine reads roles from the ID token. Most providers put roles in the access token only, unless configured otherwise. With that configuration every user gets the default role.

- **Keycloak:** the `roles` client scope writes `realm_access.roles` and `resource_access.<client-id>.roles` to the access token only. Either enable **Add to ID token** on those mappers, or add a mapper on the client. Use *User Client Role* or *User Realm Role* for roles. Use *Group Membership* with **Full group path** off for groups. Set the token claim name to `groups`, select **Multivalued**, and enable **Add to ID token**. Keep `roles.claim` at `groups`. Use one mapper per claim name.
- **Microsoft Entra ID:** under *Token configuration*, add `groups` (object IDs, one `roles.map` entry per ID) or app `roles` to the ID token.
- **Okta:** add a `groups` claim to the ID token in the authorization server.
- **AWS Cognito:** the ID token carries `cognito:groups`. Set `roles.claim` to `cognito:groups`.

### A rejected policy

When the stored policy fails validation, the engine starts and the policy is not in force. `/public` reports `configured:false`. The sign-in page offers no SSO. A sign-in attempt gets `SSO is disabled on this engine.` The tab shows the stored values and a banner with the reason. The log has `OIDC authentication is not configured: <reason>`. Correct the policy in the tab with a local administrator account. When no local administrator exists, set the value with an operator override, for example `OIE_OIDC_ROLES_DEFAULT=<role>`.

## Policy keys

Every key lives in the engine database and is edited under **Settings → OIDC Authentication**. Every key can be pinned by an operator override.

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Master switch for the policy. |
| `discovery-url` | *(empty)* | The provider's `.well-known/openid-configuration`. Required when enabled. HTTPS, or HTTP for `localhost`. |
| `client-id` | *(empty)* | The client the engine expects tokens for. Checked against `aud`. Required when enabled. |
| `client-secret` | *(empty)* | The confidential client's secret, used in the code exchange. Shown masked once stored. Required when enabled. |
| `web-administrator-url` | *(empty)* | The address browsers open the web administrator at, for example `https://oie-admin.example` or `https://engine.example:8443/oie-webadmin`. A base URL with no query, fragment, or credentials. HTTPS, or HTTP for `localhost`. The redirect URI is `<this>/oidc/callback`. Required when enabled. |
| `provider-label` | `SSO` | The sign-in button reads "Sign in with `<label>`". |
| `auto-redirect` | `false` | Send visitors to the provider at once instead of showing the button. Local sign-in stays available. |
| `scopes` | `openid profile email` | Scopes requested from the provider, separated by spaces or commas. `openid` is always included. |
| `username-claim` | `preferred_username` | The claim that becomes the engine username. |
| `username-prefix` | *(empty)* | Text put in front of the normalized username. Must match `a-z 0-9 . _ @ + : -`. |
| `allowed-algorithms` | `RS256,RS384,RS512,ES256,ES384,ES512` | Accepted signature algorithms. `HS*` is never accepted. |
| `clock-skew-seconds` | `60` | Tolerance for `exp`, `nbf`, and `iat` against the engine clock. |
| `max-token-age-seconds` | `300` | Oldest accepted `iat`. With the skew, the time an accepted token is remembered. |
| `jwks-cache-ttl-seconds` | `300` | How long the discovery document and the key set are reused. |
| `jit.enabled` | `false` | Create an engine user on first sign-in. Read *Just-in-time users* first. |
| `jit.email-claim` | `email` | Claim copied to the user's email. |
| `jit.name-claim` | `name` | Claim split into first name and last name. |
| `jit.organization-claim` | `organization` | Claim copied to the user's organization. |
| `linked-accounts` | *(empty)* | `engine-user=issuer#subject` entries, separated by commas. The only way an existing account can sign in through SSO. |
| `roles.claim` | `groups` | The claim that carries role values. A dotted path descends into nested claims. |
| `roles.map` | *(empty)* | `claim-value=RBAC role` entries, separated by commas. First match in claim order wins. |
| `roles.default` | *(empty)* | The role for a user whose claims match nothing. Required when enabled with RBAC installed, unless `roles.sync=never`. |
| `roles.sync` | `always` | `always`, `jit-only`, or `never`. See *Roles*. |
| `roles.infer` | `false` | Also accept a claim value that equals an existing RBAC role name. |

## Limitations

- RP-initiated logout and front-channel logout are not implemented. A sign-out from the engine does not end the provider session. Set the engine's `server.api.sessionmaxinactiveinterval` in line with the provider's session policy.
- Confidential clients only. The engine holds the client secret. Public clients with PKCE only are not supported.
- One identity provider per engine. The engine loads one authorization plugin.
- One role per user. `roles.map` gives the first match, not a union.
- Replay memory is per engine process. See *Token validation*.
- Removal of a user at the provider blocks the next sign-in. It does not disable or delete the engine account. Delete the engine user as well.
