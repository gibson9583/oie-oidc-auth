/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class OidcConfigLoaderTest {

    private static final String PIN = "org.openintegrationengine.oidc.client-id";

    @AfterEach
    void clearPin() {
        System.clearProperty(PIN);
    }

    @Test
    void theDefaultsCoverEveryKeyAndParseToADisabledPolicy() {
        Properties defaults = OidcConfigLoader.defaults();
        assertEquals(OidcConfigLoader.DEFAULTS.size(), defaults.size());
        OidcConfig config = OidcConfig.from(defaults);   // must not throw
        assertFalse(config.enabled());
        assertFalse(config.jitEnabled());
        assertTrue(config.allowedAlgorithms().contains("RS256"));
    }

    @Test
    void aSystemPropertyPinBeatsTheStoredValue() {
        Properties stored = new Properties();
        stored.setProperty("client-id", "from-store");
        System.setProperty(PIN, "pinned");

        assertEquals("pinned", OidcConfigLoader.withOverrides(stored).getProperty("client-id"));
    }

    @Test
    void aPolicyBodyIsReadWhetherOrNotTheXStreamEnvelopeSurvived() throws Exception {
        String policy = "{\"enabled\":\"true\",\"client-id\":\"oie-web\"}";

        for (String body : new String[] { policy, "{\"string\":" + quote(policy) + "}" }) {
            Properties parsed = OidcConfigLoader.fromJson(body);
            assertEquals("true", parsed.getProperty("enabled"), body);
            assertEquals("oie-web", parsed.getProperty("client-id"), body);
        }
    }

    /**
     * The regression that made a save answer 204 and change nothing: an
     * unrecognized body parsed to an empty policy, which then REPLACED the
     * stored one (setPluginProperties rewrites the whole group).
     */
    @Test
    void aBodyNamingNoPolicyKeyIsRejectedRatherThanReadAsAnEmptyPolicy() {
        for (String body : new String[] { "{}", "{\"nonsense\":1}", "\"just a string\"", "" }) {
            assertThrows(Exception.class, () -> OidcConfigLoader.fromJson(body), body);
        }
    }

    @Test
    void aPartialBodyCarriesOnlyItsOwnKeys() throws Exception {
        Properties parsed = OidcConfigLoader.fromJson("{\"client-id\":\"only-this\"}");

        assertEquals(1, parsed.size());
        assertEquals("only-this", parsed.getProperty("client-id"));
    }

    private static String quote(String value) {
        return '"' + value.replace("\\", "\\\\").replace("\"", "\\\"") + '"';
    }

    @Test
    void overlayingNeverMutatesTheStoredPolicy() {
        Properties stored = new Properties();
        stored.setProperty("client-id", "from-store");
        System.setProperty(PIN, "pinned");

        OidcConfigLoader.withOverrides(stored);
        assertEquals("from-store", stored.getProperty("client-id"));
    }

    /**
     * The environment half of the override mechanism. Environment variables
     * cannot be set in-process, so what is testable is the NAME each policy key
     * maps to — and that is the part most likely to be wrong, since it folds two
     * different separators into one.
     */
    @Test
    void everyPolicyKeyMapsToItsDocumentedEnvironmentVariable() {
        assertEquals("OIE_OIDC_CLIENT_ID", OidcConfigLoader.envVarName("client-id"));
        assertEquals("OIE_OIDC_JIT_ENABLED", OidcConfigLoader.envVarName("jit.enabled"));
        assertEquals("OIE_OIDC_ROLES_DEFAULT", OidcConfigLoader.envVarName("roles.default"));
        assertEquals("OIE_OIDC_JWKS_CACHE_TTL_SECONDS", OidcConfigLoader.envVarName("jwks-cache-ttl-seconds"));
        assertEquals("OIE_OIDC_JIT_ORGANIZATION_CLAIM", OidcConfigLoader.envVarName("jit.organization-claim"));
        assertEquals("org.openintegrationengine.oidc.roles.map", OidcConfigLoader.systemPropertyName("roles.map"));
    }

    /**
     * Two keys must never fold onto the same variable — one would silently
     * shadow the other, and the operator would have no way to tell which.
     */
    @Test
    void noTwoPolicyKeysShareAnEnvironmentVariable() {
        java.util.Map<String, String> byVar = new java.util.HashMap<>();
        for (String key : OidcConfigLoader.DEFAULTS.keySet()) {
            String previous = byVar.put(OidcConfigLoader.envVarName(key), key);
            assertNull(previous, "'" + key + "' and '" + previous + "' both map to "
                    + OidcConfigLoader.envVarName(key));
        }
        assertEquals(OidcConfigLoader.DEFAULTS.size(), byVar.size());
    }

    /**
     * A pin is reported from the PRESENCE of an override, not a value
     * difference — a pin whose value happens to match what is stored is still a
     * pin, and an edit to it still never takes effect. The settings tab shows
     * these read-only and the save excludes them, so a false negative here means
     * an editable field that silently reverts.
     */
    @Test
    void reportsPinnedKeysEvenWhenTheValueMatchesTheStoredOne() {
        assertTrue(OidcConfigLoader.pinned().isEmpty(), "no pins set in this test");

        System.setProperty(PIN, "identical");
        assertTrue(OidcConfigLoader.pinned().contains("client-id"));

        Properties stored = new Properties();
        stored.setProperty("client-id", "identical");   // same value as the pin
        assertTrue(OidcConfigLoader.pinned().contains("client-id"),
                "a pin is a pin even when it changes nothing");
    }
}
