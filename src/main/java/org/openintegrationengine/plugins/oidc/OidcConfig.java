/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.net.URI;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * The engine-side OIDC policy, parsed and validated from properties (see
 * {@link OidcConfigLoader} for where those come from). Validation is strict
 * when the policy is enabled — a malformed policy must fail closed at load
 * time, not at the first login.
 */
public record OidcConfig(boolean enabled, String discoveryUrl, String clientId, String clientSecret,
        String webAdministratorUrl, java.util.List<String> scopes, String providerLabel, boolean autoRedirect,
        String usernameClaim,
        Set<String> allowedAlgorithms, long clockSkewSeconds, long maxTokenAgeSeconds, long jwksCacheTtlSeconds,
        boolean jitEnabled, String emailClaim, String nameClaim, String organizationClaim, String usernamePrefix,
        Map<String, String> linkedAccounts, String rolesClaim, Map<String, String> rolesMap, String defaultRole,
        String rolesSync, boolean rolesInfer) {

    static OidcConfig from(Properties p) {
        // Type-check every key against the schema before reading any of them, so
        // a malformed value is named as itself rather than surfacing later as
        // whatever the first consumer makes of it. This is where roles.sync gets
        // checked at all: it is the only enum-valued key, and before the schema
        // existed nothing validated it — "Never" (capital N) parsed happily and
        // then meant "reconcile on every login", the exact opposite of intent.
        validateAgainstSchema(p);
        boolean enabled = bool(p, "enabled");
        String discoveryUrl = enabled ? required(p, "discovery-url") : value(p, "discovery-url");
        if (enabled) {
            requireHttps(discoveryUrl, "discovery-url");
        }
        String usernamePrefix = value(p, "username-prefix");
        // The prefix is concatenated in front of the normalized (lowercased)
        // username and the result must satisfy the username charset — reject a
        // prefix that would make every login fail.
        if (!usernamePrefix.matches("[a-z0-9._@+:-]*")) {
            throw new IllegalArgumentException("username-prefix may only contain a-z 0-9 . _ @ + : -");
        }
        // Resolved before the numeric parses below, so a policy missing BOTH a
        // client id and a valid number still reports the missing client id — the
        // more actionable of the two, and what this reported before the parses
        // were hoisted.
        String clientId = enabled ? required(p, "client-id") : value(p, "client-id");
        // The engine runs the browser-facing flow itself, so it needs the client
        // secret and must know the web administrator's own address: the redirect
        // URI registered at the provider is built from it, and it is where the
        // browser is sent back after sign-in — which is why it is validated as
        // a base URL and never taken from a request header (an open redirect
        // off a trusted origin is exactly what a spoofed Host would buy).
        String clientSecret = enabled ? required(p, "client-secret") : value(p, "client-secret");
        String webAdministratorUrl = (enabled ? required(p, "web-administrator-url") : value(p, "web-administrator-url"))
                .trim().replaceAll("/+$", "");
        if (enabled) {
            requireHttps(webAdministratorUrl, "web-administrator-url");
            URI base = URI.create(webAdministratorUrl);
            if (base.getRawQuery() != null || base.getRawFragment() != null || base.getRawUserInfo() != null) {
                throw new IllegalArgumentException("web-administrator-url must be the address browsers open the web "
                        + "administrator at — a base URL with no query, fragment, or credentials, e.g. "
                        + "https://oie-admin.example or https://engine.example:8443/oie-webadmin");
            }
        }
        java.util.List<String> scopes = scopes(value(p, "scopes"));
        // Parsed BEFORE the policy check below so a malformed number still reports
        // itself as one, rather than being masked by whatever validation happens
        // to run first.
        long clockSkew = number(p, "clock-skew-seconds");
        long maxTokenAge = number(p, "max-token-age-seconds");
        long jwksTtl = number(p, "jwks-cache-ttl-seconds");
        String rolesSync = value(p, "roles.sync");
        String defaultRole = value(p, "roles.default").trim();
        // With RBAC installed, a returning user whose claims resolve to no role
        // would keep whatever role they already had — so revoking their group at
        // the IdP would not remove their engine access. Rather than decide what
        // to do in that case, make it unreachable: require a default, so claims
        // always resolve to something.
        //
        // Narrowly scoped, because a rejection here takes SSO down (see the
        // plugin's apply()). Not without RBAC — there are no roles to assign, so
        // the key would be meaningless. Not with roles.sync=never — the assigner
        // returns before ever reading a default, so no stale role can be kept by
        // this extension, and demanding a value it will not read would break a
        // deliberate hand-managed setup for nothing.
        if (enabled && !"never".equals(rolesSync) && RbacRoleAssigner.isInstalled() && defaultRole.isEmpty()) {
            throw new IllegalArgumentException("roles.default is required when OIDC is enabled and the "
                    + "role-based-access-control extension is installed. Set it to the role a user should hold when "
                    + "their claims match no roles.map entry — otherwise a user whose IdP groups are revoked would "
                    + "silently keep the role they already had. Set roles.sync=never instead if this extension should "
                    + "not manage roles at all. As an emergency override without the UI, set OIE_OIDC_ROLES_DEFAULT.");
        }
        return new OidcConfig(enabled,
                discoveryUrl,
                clientId,
                clientSecret,
                webAdministratorUrl,
                scopes,
                value(p, "provider-label").trim().isEmpty() ? "SSO" : value(p, "provider-label").trim(),
                bool(p, "auto-redirect"),
                value(p, "username-claim"),
                csv(value(p, "allowed-algorithms")),
                clockSkew,
                maxTokenAge,
                jwksTtl,
                // FALSE when absent, matching what OidcConfigLoader seeds. The two
                // disagreeing meant any stored policy without the key — an upgrade,
                // or hand-written properties — silently turned JIT provisioning ON
                // while the settings tab, which also defaults to "No", showed it
                // off. Provisioning users is not a default to infer.
                bool(p, "jit.enabled"),
                value(p, "jit.email-claim"),
                value(p, "jit.name-claim"),
                value(p, "jit.organization-claim"),
                usernamePrefix,
                pairs(value(p, "linked-accounts")),
                value(p, "roles.claim"),
                pairs(value(p, "roles.map")),
                defaultRole,
                rolesSync,
                bool(p, "roles.infer"));
    }

    /**
     * Identity endpoints must be HTTPS — a JWKS or discovery document fetched
     * over plain HTTP could be tampered with in transit, which would let an
     * attacker mint accepted identities. Localhost is exempt for development,
     * mirroring the web tier's rule.
     */
    static void requireHttps(String url, String what) {
        URI parsed;
        try {
            parsed = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(what + " is not a valid URL");
        }
        String host = parsed.getHost();
        boolean local = "localhost".equals(host) || "127.0.0.1".equals(host);
        if (!"https".equalsIgnoreCase(parsed.getScheme()) && !local) {
            throw new IllegalArgumentException(what + " must use HTTPS (HTTP is allowed only for localhost)");
        }
    }

    private static String required(Properties p, String key) {
        String value = p.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(key + " is required");
        }
        return value.trim();
    }

    /** The stored value, or the schema's default when the key is absent. */
    private static String value(Properties p, String key) {
        return p.getProperty(key, PolicySchema.of(key).fallback());
    }

    private static boolean bool(Properties p, String key) {
        return PolicySchema.parseBoolean(key, value(p, key));
    }

    private static long number(Properties p, String key) {
        return Long.parseLong(value(p, key));
    }

    /**
     * Type-checks every present key. Numbers report themselves as numbers,
     * booleans refuse a value they would otherwise silently read as false, and
     * enums name the values they accept — so a typo says what is wrong with it
     * rather than taking effect as some default.
     */
    private static void validateAgainstSchema(Properties p) {
        for (PolicySchema.Key key : PolicySchema.KEYS) {
            String raw = p.getProperty(key.name());
            if (raw == null) {
                continue;
            }
            switch (key.kind()) {
                case BOOLEAN -> PolicySchema.parseBoolean(key.name(), raw);
                case NUMBER -> {
                    try {
                        Long.parseLong(raw.trim());
                    } catch (NumberFormatException e) {
                        throw new IllegalArgumentException(
                                key.name() + " must be a whole number, but was \"" + raw + "\"");
                    }
                }
                case ENUM -> {
                    if (!key.choices().contains(raw.trim())) {
                        throw new IllegalArgumentException(key.name() + " must be one of "
                                + String.join(", ", key.choices()) + ", but was \"" + raw + "\"");
                    }
                }
                default -> { /* TEXT, URL and PAIRS are checked where they are used */ }
            }
        }
    }

    /**
     * Space- or comma-separated scopes, {@code openid} always first: without it
     * the provider returns no ID token at all, and the failure would surface as
     * "token exchange failed" rather than as the missing scope.
     */
    static java.util.List<String> scopes(String value) {
        java.util.List<String> out = new java.util.ArrayList<>();
        out.add("openid");
        for (String scope : value.split("[\\s,]+")) {
            if (!scope.isBlank() && !out.contains(scope.trim())) {
                out.add(scope.trim());
            }
        }
        return java.util.Collections.unmodifiableList(out);
    }

    private static Set<String> csv(String value) {
        return new LinkedHashSet<>(Arrays.stream(value.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList());
    }

    /** Parses comma-separated {@code key=value} entries, preserving order. */
    static Map<String, String> pairs(String value) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String item : value.split(",")) {
            int eq = item.indexOf('=');
            if (eq > 0) {
                out.put(item.substring(0, eq).trim(), item.substring(eq + 1).trim());
            }
        }
        return out;
    }
}
