/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
}
