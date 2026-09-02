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
public record OidcConfig(boolean enabled, String discoveryUrl, String clientId, String usernameClaim,
        Set<String> allowedAlgorithms, long clockSkewSeconds, long maxTokenAgeSeconds, long jwksCacheTtlSeconds,
        boolean jitEnabled, String emailClaim, String nameClaim, String organizationClaim, String usernamePrefix,
        Map<String, String> linkedAccounts, String rolesClaim, Map<String, String> rolesMap, String defaultRole,
        String rolesSync, boolean rolesInfer) {

    static OidcConfig from(Properties p) {
        boolean enabled = bool(p, "enabled", false);
        String discoveryUrl = enabled ? required(p, "discovery-url") : p.getProperty("discovery-url", "");
        if (enabled) {
            requireHttps(discoveryUrl, "discovery-url");
        }
        String usernamePrefix = p.getProperty("username-prefix", "");
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
        String clientId = enabled ? required(p, "client-id") : p.getProperty("client-id", "");
        // Parsed BEFORE the policy check below so a malformed number still reports
        // itself as one, rather than being masked by whatever validation happens
        // to run first.
        long clockSkew = number(p, "clock-skew-seconds", 60);
        long maxTokenAge = number(p, "max-token-age-seconds", 300);
        long jwksTtl = number(p, "jwks-cache-ttl-seconds", 300);
        String rolesSync = p.getProperty("roles.sync", "always");
        String defaultRole = p.getProperty("roles.default", "").trim();
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
                p.getProperty("username-claim", "preferred_username"),
                csv(p.getProperty("allowed-algorithms", "RS256,RS384,RS512,ES256,ES384,ES512")),
                clockSkew,
                maxTokenAge,
                jwksTtl,
                // FALSE when absent, matching what OidcConfigLoader seeds. The two
                // disagreeing meant any stored policy without the key — an upgrade,
                // or hand-written properties — silently turned JIT provisioning ON
                // while the settings tab, which also defaults to "No", showed it
                // off. Provisioning users is not a default to infer.
                bool(p, "jit.enabled", false),
                p.getProperty("jit.email-claim", "email"),
                p.getProperty("jit.name-claim", "name"),
                p.getProperty("jit.organization-claim", "organization"),
                usernamePrefix,
                pairs(p.getProperty("linked-accounts", "")),
                p.getProperty("roles.claim", "groups"),
                pairs(p.getProperty("roles.map", "")),
                defaultRole,
                rolesSync,
                bool(p, "roles.infer", false));
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

    private static boolean bool(Properties p, String key, boolean fallback) {
        return Boolean.parseBoolean(p.getProperty(key, String.valueOf(fallback)));
    }

    private static long number(Properties p, String key, long fallback) {
        return Long.parseLong(p.getProperty(key, String.valueOf(fallback)));
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
