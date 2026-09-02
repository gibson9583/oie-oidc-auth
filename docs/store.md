# OIDC Authentication

Adds generic OpenID Connect SSO to the web administrator while preserving named-user engine audit attribution. Supports discovery/JWKS validation, JIT provisioning, durable subject binding, local-login fallback, and optional RBAC role mapping.

**Both halves are required.** This extension validates tokens and owns identity, but it does not talk to your provider directly — the browser-facing Authorization Code + PKCE flow runs in the web administrator's **Node server**, which holds a **client secret** you configure there. So you need: this extension installed on the engine, the web administrator running as the Node deployment (the WAR has no server half and never offers SSO), and a confidential client registered at your provider with the redirect URI `<web-administrator-origin>/oidc/callback`. The secret lives only in web-tier deployment configuration; the engine neither stores nor returns it.

Register one redirect URI, install RBAC first if you intend to enable JIT provisioning, and read the README's *Policy keys* and *Limitations* sections before rollout — notably that logout does not end the provider session and that only one identity provider per engine is possible.
