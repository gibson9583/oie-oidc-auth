# OIDC Authentication 1.0.1

Security release.

## Fixed

- **The client secret is encrypted before it is stored.** It is sealed with
  the engine's own key, decrypted only in memory when the policy is applied,
  and shown as ciphertext (`enc:…`) wherever stored plugin properties are
  displayed raw, configuration exports included. A stored value that is not
  sealed, or that this engine's key cannot decrypt, is refused, and the tab
  says to enter the secret again. An `OIE_OIDC_CLIENT_SECRET` pin is applied
  before the stored value is judged, so it can rescue an engine whose stored
  secret no longer opens.

## Changed

- The engine log is quiet at the default level. The state line written at
  startup and after each save (`OIDC authentication is ACTIVE …` or
  `… disabled …`) and the account-rename line are DEBUG. The kill switch, a
  rejected policy, JIT provisioning without RBAC, and refused sign-ins stay
  WARN. Set the logger `org.openintegrationengine.plugins.oidc` to DEBUG to
  see the state line.

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
