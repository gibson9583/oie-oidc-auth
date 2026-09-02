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

/**
 * What a save writes to the engine, which had no coverage at all.
 *
 * <p>A review neutered seven of this plugin's most carefully commented guards
 * at once — including two of the rules below — and the entire suite stayed
 * green. The tests were dense where the logic is simple and silent where it is
 * delicate: this sequence decides the stored policy, and
 * {@code setPluginProperties} REPLACES the whole property group, so a mistake
 * here does not corrupt one key, it rewrites the configuration.</p>
 *
 * <p>These call {@link OidcAdminServlet#merge} directly. An earlier draft
 * restated the merge in this file instead, because the servlet needs a JAX-RS
 * request context to construct — and proved only that the copy here agreed with
 * itself: deleting the pinned-key strip from the servlet left all of it green.
 * That is why the rule lives in one method now.</p>
 */
class OidcAdminServletMergeTest {

    private static final String PIN = "org.openintegrationengine.oidc.client-id";

    @AfterEach
    void clearPin() {
        System.clearProperty(PIN);
    }

    private static Properties stored() {
        Properties p = OidcConfigLoader.defaults();
        p.setProperty("enabled", "true");
        p.setProperty("discovery-url", "https://issuer.example/.well-known/openid-configuration");
        p.setProperty("client-id", "from-store");
        p.setProperty("roles.default", "Viewer");
        return p;
    }

    /**
     * A body carrying some keys updates those and leaves the rest. Replacing
     * rather than merging would blank every key the form did not send, and the
     * engine would persist that as the whole policy.
     */
    @Test
    void aPartialBodyLeavesUnmentionedKeysIntact() throws Exception {
        Properties merged = OidcAdminServlet.merge(stored(), "{\"username-claim\":\"upn\"}");

        assertEquals("upn", merged.getProperty("username-claim"));
        assertEquals("from-store", merged.getProperty("client-id"));
        assertEquals("Viewer", merged.getProperty("roles.default"));
        assertEquals("true", merged.getProperty("enabled"));
    }

    /**
     * A pinned key is never written back. The GET serves EFFECTIVE values, so
     * the form holds whatever an OIE_OIDC_* variable overrode — and saving would
     * bake the pin into the stored policy. Nothing changes while the pin is in
     * place, which is what makes it dangerous: remove the variable later and the
     * pin's value has silently become permanent. The worst shape is an operator
     * using OIE_OIDC_ENABLED=false as an emergency off, someone pressing Save,
     * and SSO switching itself back on when the variable is cleared.
     */
    @Test
    void aPinnedKeyIsNotPersisted() throws Exception {
        System.setProperty(PIN, "pinned-value");

        // The form round-trips the effective value, exactly as the GET served it.
        Properties merged = OidcAdminServlet.merge(stored(), "{\"client-id\":\"pinned-value\"}");
        assertEquals("from-store", merged.getProperty("client-id"),
                "the stored policy must be untouched while the pin is in force");

        // And an unpinned key in the same body still saves.
        Properties both = OidcAdminServlet.merge(stored(),
                "{\"client-id\":\"pinned-value\",\"username-claim\":\"upn\"}");
        assertEquals("from-store", both.getProperty("client-id"));
        assertEquals("upn", both.getProperty("username-claim"));
    }

    /**
     * An invalid policy never reaches the property store. merge() is the only
     * route to saveAndApply, so validating here means a rejected policy cannot
     * be persisted — saving first and validating after would leave the database
     * holding a configuration that cannot load, recoverable only outside the UI.
     */
    @Test
    void anInvalidBodyIsRejectedBeforeItCanBePersisted() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> OidcAdminServlet.merge(stored(), "{\"roles.sync\":\"Never\"}"));
        assertTrue(e.getMessage().contains("roles.sync"), e.getMessage());

        assertThrows(IllegalArgumentException.class,
                () -> OidcAdminServlet.merge(stored(), "{\"discovery-url\":\"\"}"));
        assertThrows(IllegalArgumentException.class,
                () -> OidcAdminServlet.merge(stored(), "{\"max-token-age-seconds\":\"soon\"}"));
    }

    /**
     * The reserved reporting keys the GET adds describe effective state, not
     * policy. They must not survive a round trip through the form and be stored
     * as if they were settings.
     */
    @Test
    void reservedReportingKeysNeverBecomePolicy() throws Exception {
        Properties merged = OidcAdminServlet.merge(stored(),
                "{\"_killSwitch\":true,\"_error\":\"boom\",\"_pinned\":[\"client-id\"],"
                        + "\"_redirectUri\":\"https://x/oidc/callback\",\"_schema\":[],\"username-claim\":\"upn\"}");

        for (String reserved : new String[] { "_killSwitch", "_error", "_pinned", "_redirectUri", "_schema" }) {
            assertFalse(merged.containsKey(reserved), reserved + " must not be persisted");
        }
        assertEquals("upn", merged.getProperty("username-claim"), "the real key in the same body still applies");
    }

    /**
     * A body naming no recognized key is refused rather than read as an empty
     * policy — the regression that made a save answer 204 and wipe the stored
     * configuration while still reporting success.
     */
    @Test
    void aBodyWithNoRecognizedKeysIsRefused() {
        for (String body : new String[] { "{}", "{\"nonsense\":1}", "{\"_killSwitch\":true}" }) {
            assertThrows(Exception.class, () -> OidcAdminServlet.merge(stored(), body), body);
        }
    }
}
