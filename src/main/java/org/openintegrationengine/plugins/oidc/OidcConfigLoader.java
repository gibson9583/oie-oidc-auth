/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The policy's key catalog, defaults, operator overrides, and the save
 * entry point. The policy is stored in the extension's own configuration
 * group ({@link PolicyStore}), read once at startup by the plugin and applied
 * in memory; a save writes the store and applies in the same step, so the
 * store is never read on a request thread.
 *
 * <p>Operator overrides: an {@code org.openintegrationengine.oidc.*} system
 * property or {@code OIE_OIDC_*} environment variable (env wins) overlays any
 * stored value at apply time — pinning for automated deployments; overrides
 * are never persisted.</p>
 */
public final class OidcConfigLoader {

    /**
     * The key catalog, from {@link PolicySchema}. Kept as a field because the
     * name is used widely; the list itself lives in one place now, so this and
     * {@link OidcConfig}'s per-key defaults can no longer drift apart the way
     * jit.enabled once did.
     */
    static final Map<String, String> DEFAULTS = PolicySchema.defaults();

    private OidcConfigLoader() {}

    static Properties defaults() {
        Properties p = new Properties();
        DEFAULTS.forEach(p::setProperty);
        return p;
    }

    /**
     * Reads a policy body into properties, tolerating either wire shape. A
     * {@code String} servlet parameter is meant to arrive already unwrapped from
     * the engine's XStream envelope, but which JAX-RS reader wins for a
     * {@code String} entity is a provider-ordering detail — so an envelope that
     * survived this far is unwrapped instead of being misread.
     *
     * <p>A body naming none of the policy keys is REJECTED, not read as an empty
     * policy: the caller persists what this returns, and the engine's
     * {@code setPluginProperties} replaces the whole group, so answering a
     * wire-shape mismatch with an empty result silently wipes a live policy and
     * still reports success.</p>
     */
    static Properties fromJson(String body) throws Exception {
        ObjectMapper json = new ObjectMapper();
        JsonNode node = json.readTree(body == null ? "" : body);
        if (node.isObject() && node.size() == 1 && node.path("string").isTextual()) {
            node = json.readTree(node.get("string").asText());
        }
        if (!node.isObject()) {
            throw new IllegalArgumentException("configuration must be a JSON object");
        }
        Properties properties = new Properties();
        for (String key : DEFAULTS.keySet()) {
            JsonNode value = node.get(key);
            if (value != null && !value.isNull()) {
                properties.setProperty(key, value.asText());
            }
        }
        if (properties.isEmpty()) {
            StringBuilder names = new StringBuilder();
            node.fieldNames().forEachRemaining(n -> names.append(names.length() == 0 ? "" : ", ").append(n));
            throw new IllegalArgumentException("configuration carried no recognized keys (got: "
                    + (names.length() == 0 ? "no fields" : names) + ")");
        }
        return properties;
    }

    /**
     * Policy keys an operator has pinned through the environment or a system
     * property. Derived from the PRESENCE of an override, not from a value
     * difference: a pin whose value happens to match what is stored is still a
     * pin, and an edit to it will still never take effect.
     */
    static java.util.Set<String> pinned() {
        java.util.Set<String> keys = new java.util.LinkedHashSet<>();
        for (String key : DEFAULTS.keySet()) {
            if (System.getProperty(systemPropertyName(key)) != null || System.getenv(envVarName(key)) != null) {
                keys.add(key);
            }
        }
        return keys;
    }

    /** The system property that pins {@code key}. */
    static String systemPropertyName(String key) {
        return "org.openintegrationengine.oidc." + key;
    }

    /**
     * The environment variable that pins {@code key}: uppercased, with dots and
     * hyphens folded to underscores. Extracted so the rule is verifiable —
     * environment variables cannot be set in-process, so a test can only check
     * the NAME this computes, and a mangling that collapsed two policy keys onto
     * one variable would otherwise let one silently shadow the other.
     */
    static String envVarName(String key) {
        return "OIE_OIDC_" + key.toUpperCase(Locale.ROOT).replace('.', '_').replace('-', '_');
    }

    /** The stored policy plus operator pins — what the engine actually enforces. */
    static Properties withOverrides(Properties stored) {
        Properties p = new Properties();
        if (stored != null) {
            p.putAll(stored);
        }
        for (String key : DEFAULTS.keySet()) {
            String sys = System.getProperty(systemPropertyName(key));
            String env = System.getenv(envVarName(key));
            if (sys != null) {
                p.setProperty(key, sys);
            }
            if (env != null) {
                p.setProperty(key, env);
            }
        }
        return p;
    }

    /**
     * Persists the policy and applies it to the live plugin in one step —
     * the saved properties themselves become the active configuration; the
     * store is never read back.
     */
    static void saveAndApply(Properties properties) throws IOException {
        OidcAuthorizationPlugin.saveAndApplyToInstance(properties);
    }
}
