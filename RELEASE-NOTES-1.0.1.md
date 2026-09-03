# OIDC Authentication 1.0.1

Security release. Use it with role-based-access-control 1.1.3 or newer.

## Fixed

- **The client secret was readable by any role.** The policy is stored in the
  engine's per-plugin properties slot, and the engine's generic
  `GET /extensions/<name>/properties` returns that slot raw with no permission
  of its own; the RBAC extension allowed the operation because nothing had
  mapped it. One request returned the secret in the clear. The secret is now
  encrypted with the engine's own key before it is stored, decrypted only in
  memory when the policy is applied, and shown as ciphertext (`enc:…`) by
  every raw view and by configuration exports. A stored value that is not
  sealed, or that this engine's key cannot decrypt, is refused, and the tab
  says to enter the secret again. An `OIE_OIDC_CLIENT_SECRET` pin is applied
  before the stored value is judged, so it can rescue an engine whose stored
  secret no longer opens.
- role-based-access-control 1.1.3 gates the engine's generic plugin-properties
  endpoints by `manageExtensions` and refuses names that are not installed
  extensions, so those endpoints can no longer read or rewrite any plugin's
  stored properties, or any other configuration group, for any role. Until an
  engine runs that release, encryption is the only protection for the secret,
  and any role can still overwrite the policy; a rewritten secret is refused
  at load rather than used.

## Upgrading from 1.0.0

Every 1.0.0 install stores the secret in the clear, and this release refuses
it. **SSO is off after the upgrade until the client secret is entered again**
under Settings → OIDC Authentication and saved, after which it is stored
encrypted. If the tab cannot be reached, set `OIE_OIDC_CLIENT_SECRET` in the
engine's environment instead. Everything else in the policy carries over.

A configuration export taken with 1.0.1 carries the secret encrypted under the
exporting engine's key. Restored onto a different engine, the secret must be
entered again.

## Docs

- The README is now a reference, and a [wiki](https://github.com/gibson9583/oie-oidc-auth/wiki)
  covers installation, configuration, the sign-in flow, users and roles,
  provider guides for Keycloak, Microsoft Entra ID, Okta, and AWS Cognito, and
  troubleshooting.
- Requires the OIE web administrator 0.9.0 or newer.

## Verification

138 unit tests, including the seal and open round trip, a save that carries
the mask leaving the sealed value unchanged, fail-closed on an unsealed or
foreign-key value, and the pin rescue.
