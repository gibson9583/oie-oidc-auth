# OIDC Authentication

Adds generic OpenID Connect SSO to the web administrator while preserving named-user engine audit attribution. Supports discovery/JWKS validation, JIT provisioning, durable subject binding, local-login fallback, and optional RBAC role mapping.

**Everything is configured on the engine.** This extension runs the whole Authorization Code + PKCE flow itself — provider redirect, code exchange with the client secret, token validation — and hands the web administrator a one-time ticket to sign in with. So you need: this extension installed on the engine, a confidential client registered at your provider with the redirect URI `<web-administrator-url>/oidc/callback`, and the policy filled in under **Settings → OIDC Authentication** (discovery URL, client ID and secret, the web administrator's URL). The web administrator needs no configuration of its own. The secret is stored in the engine's policy and never returned by the API.

Register one redirect URI, install RBAC first if you intend to enable JIT provisioning, and read the README's *Policy keys* and *Limitations* sections before rollout — notably that logout does not end the provider session and that only one identity provider per engine is possible.
