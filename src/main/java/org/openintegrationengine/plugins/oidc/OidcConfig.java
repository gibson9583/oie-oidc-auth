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
        return new OidcConfig(enabled,
                discoveryUrl,
                enabled ? required(p, "client-id") : p.getProperty("client-id", ""),
                p.getProperty("username-claim", "preferred_username"),
                csv(p.getProperty("allowed-algorithms", "RS256,RS384,RS512,ES256,ES384,ES512")),
                number(p, "clock-skew-seconds", 60),
                number(p, "max-token-age-seconds", 300),
                number(p, "jwks-cache-ttl-seconds", 300),
                bool(p, "jit.enabled", true),
                p.getProperty("jit.email-claim", "email"),
                p.getProperty("jit.name-claim", "name"),
                p.getProperty("jit.organization-claim", "organization"),
                usernamePrefix,
                pairs(p.getProperty("linked-accounts", "")),
                p.getProperty("roles.claim", "groups"),
                pairs(p.getProperty("roles.map", "")),
                p.getProperty("roles.default", ""),
                p.getProperty("roles.sync", "always"),
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
