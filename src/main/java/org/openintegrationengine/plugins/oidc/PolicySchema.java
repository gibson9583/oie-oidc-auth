/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The policy's single source of truth: every key, its default, its type, and
 * how it is presented.
 *
 * <p>This exists because the key set used to be written out four times — the
 * seeded defaults, the parser's inline fallbacks, the settings tab's field
 * list, and the README table — kept in agreement by hand. They had already
 * fallen out of agreement once: {@code jit.enabled} seeded {@code false} but
 * parsed as {@code true} when absent, so a policy missing the key silently
 * provisioned users while the tab displayed the feature as off. Anything that
 * has to be edited in four places to stay correct will eventually be edited in
 * three.</p>
 *
 * <p>{@link OidcConfigLoader} takes its defaults from here, {@link OidcConfig}
 * takes both defaults and type validation from here, and the settings tab
 * renders from the copy the admin servlet sends it. Adding a key means adding
 * one row.</p>
 */
public final class PolicySchema {

    /**
     * What a value means, which decides both how it is validated and which
     * control the settings tab renders.
     */
    public enum Kind {
        /** Free text. */
        TEXT,
        /** Absolute http(s) URL; plain HTTP allowed only for localhost. */
        URL,
        /** Whole number, parsed strictly. */
        NUMBER,
        /** Strictly "true" or "false" — see {@link #parseBoolean}. */
        BOOLEAN,
        /** One of {@link Key#choices()}. */
        ENUM,
        /** Comma-separated {@code key=value} entries. */
        PAIRS,
        /**
         * Free text that is never echoed back: the settings tab receives
         * {@link #SECRET_MASK} in place of a stored value, and a save carrying
         * the mask leaves the stored value untouched.
         */
        SECRET
    }

    /** What a SECRET reads as once set. Never a plausible real value. */
    public static final String SECRET_MASK = "********";

    /**
     * @param name    the property name, as stored and as written in config
     * @param fallback value when the key is absent
     * @param kind    validation and control type
     * @param choices for {@link Kind#ENUM}, the permitted values in display order
     * @param label   the settings tab's field label
     */
    public record Key(String name, String fallback, Kind kind, List<String> choices, String label) {

        Key(String name, String fallback, Kind kind, String label) {
            this(name, fallback, kind, List.of(), label);
        }
    }

    public static final List<Key> KEYS = List.of(
            new Key("enabled", "false", Kind.BOOLEAN, "Enable OIDC login"),
            new Key("discovery-url", "", Kind.URL, "Discovery URL"),
            new Key("client-id", "", Kind.TEXT, "Client ID"),
            new Key("client-secret", "", Kind.SECRET, "Client secret"),
            new Key("web-administrator-url", "", Kind.URL, "Web administrator URL"),
            new Key("provider-label", "SSO", Kind.TEXT, "Sign-in button label"),
            new Key("auto-redirect", "false", Kind.BOOLEAN, "Send visitors straight to the provider"),
            new Key("scopes", "openid profile email", Kind.TEXT, "Scopes"),
            new Key("username-claim", "preferred_username", Kind.TEXT, "Username claim"),
            new Key("allowed-algorithms", "RS256,RS384,RS512,ES256,ES384,ES512", Kind.TEXT, "Allowed algorithms"),
            new Key("clock-skew-seconds", "60", Kind.NUMBER, "Clock skew (seconds)"),
            new Key("max-token-age-seconds", "300", Kind.NUMBER, "Maximum token age (seconds)"),
            new Key("jwks-cache-ttl-seconds", "300", Kind.NUMBER, "JWKS cache TTL (seconds)"),
            new Key("jit.enabled", "false", Kind.BOOLEAN, "JIT provision unknown users"),
            new Key("jit.email-claim", "email", Kind.TEXT, "Email claim"),
            new Key("jit.name-claim", "name", Kind.TEXT, "Name claim"),
            new Key("jit.organization-claim", "organization", Kind.TEXT, "Organization claim"),
            new Key("username-prefix", "", Kind.TEXT, "Username prefix"),
            new Key("linked-accounts", "", Kind.PAIRS, "Linked accounts"),
            new Key("roles.claim", "groups", Kind.TEXT, "Roles claim"),
            new Key("roles.map", "", Kind.PAIRS, "Claim-to-role mappings"),
            new Key("roles.default", "", Kind.TEXT, "Default role"),
            new Key("roles.sync", "always", Kind.ENUM, List.of("always", "jit-only", "never"), "Role synchronization"),
            new Key("roles.infer", "false", Kind.BOOLEAN, "Infer roles by name"));

    private static final Map<String, Key> BY_NAME;
    static {
        Map<String, Key> index = new LinkedHashMap<>();
        for (Key key : KEYS) {
            index.put(key.name(), key);
        }
        BY_NAME = Collections.unmodifiableMap(index);
    }

    private PolicySchema() {}

    public static Key of(String name) {
        Key key = BY_NAME.get(name);
        if (key == null) {
            throw new IllegalArgumentException("unknown policy key: " + name);
        }
        return key;
    }

    /** Every key at its default, in declaration order. */
    public static Map<String, String> defaults() {
        Map<String, String> out = new LinkedHashMap<>();
        for (Key key : KEYS) {
            out.put(key.name(), key.fallback());
        }
        return Collections.unmodifiableMap(out);
    }

    /**
     * Strict boolean parsing, deliberately unlike {@link Boolean#parseBoolean},
     * which maps every unrecognized string — including a typo, and including
     * {@code "no"} — to {@code false}. For {@code enabled} that reads as "your
     * typo silently switched SSO off"; for {@code jit.enabled} it reads the
     * other way. Accepts the spellings a hand-written or templated config
     * plausibly produces, and refuses anything else rather than guessing.
     */
    public static boolean parseBoolean(String key, String value) {
        String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "true", "yes", "on", "1" -> true;
            case "false", "no", "off", "0" -> false;
            default -> throw new IllegalArgumentException(
                    key + " must be true or false, but was \"" + value + "\"");
        };
    }
}
