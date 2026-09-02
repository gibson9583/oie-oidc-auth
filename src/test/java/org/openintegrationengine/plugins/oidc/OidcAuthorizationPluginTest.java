/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.Properties;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.LoginStatus.Status;

/**
 * The façade contract: null ONLY for unprefixed passwords (local fall-through
 * keeps engine lockout and break-glass), FAIL — never null — for anything
 * {@code oidc:}-prefixed, and the kill switch wins over any configuration.
 */
class OidcAuthorizationPluginTest {

    private static final String KILL_SWITCH = "org.openintegrationengine.oidc.disabled";

    @AfterEach
    void clearKillSwitch() {
        System.clearProperty(KILL_SWITCH);
    }

    private static OidcAuthorizationPlugin configured() throws Exception {
        Properties p = new Properties();
        p.setProperty("enabled", "true");
        p.setProperty("roles.default", "Viewer");   // required whenever RBAC is on the classpath
        p.setProperty("discovery-url", "https://issuer.example/.well-known/openid-configuration");
        p.setProperty("client-id", "client");
        OidcConfig config = OidcConfig.from(p);

        // Discovery that always fails: any oidc: login must FAIL closed.
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(), any())).thenThrow(new IOException("IdP unreachable"));
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin();
        plugin.configure(config, new OidcTokenValidator(config, new DiscoveryClient(http)));
        return plugin;
    }

    @Test
    void ignoresUnprefixedPasswords() throws Exception {
        assertNull(configured().authorizeUser("admin", "hunter2"));
        assertNull(configured().authorizeUser("admin", null));
    }

    @Test
    void failsClosedWhenUnconfigured() throws Exception {
        LoginStatus status = new OidcAuthorizationPlugin().authorizeUser("jdoe", "oidc:token");
        assertNotNull(status, "an oidc: assertion must never fall through to local auth");
        assertEquals(Status.FAIL, status.getStatus());
    }

    @Test
    void failsClosedOnAnyValidationError() throws Exception {
        LoginStatus status = configured().authorizeUser("jdoe", "oidc:not-a-real-token");
        assertNotNull(status);
        assertEquals(Status.FAIL, status.getStatus());
    }

    @Test
    void theKillSwitchBeatsAValidConfiguration() throws Exception {
        System.setProperty(KILL_SWITCH, "true");
        LoginStatus status = configured().authorizeUser("jdoe", "oidc:token");
        assertNotNull(status);
        assertEquals(Status.FAIL, status.getStatus());
    }

    @Test
    void theEnginePushedPolicyIsAppliedAndServedBack() {
        // The native contract: init/update hand the plugin its policy; the
        // plugin serves it from memory and never reads the property store.
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin();
        Properties stored = OidcConfigLoader.defaults();
        stored.setProperty("enabled", "true");
        stored.setProperty("roles.default", "Viewer");
        stored.setProperty("discovery-url", "https://issuer.example/.well-known/openid-configuration");
        stored.setProperty("client-id", "client");
        plugin.init(stored);

        assertEquals("client", OidcAuthorizationPlugin.currentProperties().getProperty("client-id"));
        assertEquals(true, OidcAuthorizationPlugin.currentConfig().enabled());

        Properties disabled = OidcConfigLoader.defaults();
        plugin.update(disabled);
        assertEquals(false, OidcAuthorizationPlugin.currentConfig().enabled());
    }

    @Test
    void throttlesARunawayHintButStillNeverReturnsNull() throws Exception {
        OidcAuthorizationPlugin plugin = configured();
        for (int i = 0; i < 25; i++) {
            LoginStatus status = plugin.authorizeUser("guessing", "oidc:bad");
            assertNotNull(status);
            assertEquals(Status.FAIL, status.getStatus());
        }
    }
}
