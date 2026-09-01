# OIE OIDC Authentication

Engine-side authorization extension for the OIE web administrator's native OpenID Connect login. It validates signed ID tokens itself, creates real named engine users when configured, permanently binds each account to `issuer#subject`, and optionally maps provider groups to the RBAC extension. Local password login is untouched.

## Install and configure

Build with Java 17 and an OIE 4.6.0 installation:

```sh
OIE_HOME=/path/to/oie mvn clean package
```

Extract `target/oidcauth-0.1.0.zip` into the engine extensions directory and restart. Verify the extension loaded before touching the UI: the engine log must contain an `OIDC authentication` init line (`... is disabled` until configured); without it, no endpoint, permission, or settings tab exists.

Permissions with RBAC installed: users on the **admin role** (`is_admin`) hold `manageOIDC` — like every extension permission — automatically and implicitly. Do **not** try to tick it on the admin role; that role is deliberately read-only in the role editor because its holders bypass stored permissions. Grant `manageOIDC` only to non-admin roles that should manage SSO policy. Without RBAC the panel is available to any signed-in user. The web module mirrors RBAC's own settings plugin: it loads the signed-in user's effective permission set during registration and only registers the tab when `manageOIDC` is present (or RBAC is absent).

Configure under **Settings → OIDC Authentication**: tick **Enable OIDC login** to unlock the fields, then use **Save**, **Refresh**, and **Test connection** in the tab's task pane. Save validates the policy first, persists it to the **engine database** (the engine's native per-plugin properties, so it rides normal database backups), and reloads the live plugin — no engine restart. Test connection verifies discovery and JWKS reachability for the values currently on the form.

The plugin follows the engine's native settings lifecycle: defaults are seeded into the store on first install (and newly added keys are merged on upgrade), the engine pushes the stored policy into the plugin at startup, and saves persist and apply in one step — the plugin never reads the property store at request time. Automated installs provision entirely through `OIE_OIDC_*` environment variables (or system properties); there is no config file.

The extension exposes only enabled state, discovery URL, and client ID from its narrow pre-auth `/api/extensions/oidcauth/public` endpoint. The Node web tier uses that metadata to decide whether to advertise SSO and to perform authorization-code exchange. The client secret remains only in web deployment configuration; it is never stored by or returned from the engine.

Every property can be overridden with an `OIE_OIDC_*` environment variable (dots and hyphens become underscores) or `org.openintegrationengine.oidc.*` system property; overrides win over the stored (UI-managed) policy, so operators can pin values the form cannot change. `OIE_OIDC_DISABLED=true` is the emergency kill switch and needs neither the database nor the UI.

`roles.claim` accepts a dotted path into nested claims, not just a top-level name — Keycloak puts realm roles at `realm_access.roles` and client roles at `resource_access.<client-id>.roles`, and only group membership is flat. A claim whose literal name contains dots is still matched first, so existing configurations keep their meaning. Whichever claim you choose, its Keycloak mapper needs **Add to ID token** switched on: this extension validates the ID token, while Keycloak's role mappers default to the access token only — a mismatch that looks exactly like "roles are being ignored".

Existing users are rejected unless their exact `issuer#subject` is present in `linked-accounts`. New JIT users receive the binding automatically. `roles.map` and `linked-accounts` use comma-separated `key=value` entries (the settings panel renders them as row editors). Role resolution per login: first explicit `roles.map` hit in claim order, then — with `roles.infer` enabled — the first claim value exactly matching an existing RBAC role name, then `roles.default`. Explicit mappings always beat inference, so the two compose: infer the bulk, map the exceptions. Leave `roles.infer` off unless the claim is curated (a dedicated client-role mapper): any matching value, including `Administrator`, grants that role. RBAC failures never block authentication, and the extension will not demote the last administrator.

The web administrator redirect URI is `<web-origin>/oidc/callback`. RP-initiated and front-channel logout are not implemented. Keep the engine API session timeout aligned with the provider's session policy.
