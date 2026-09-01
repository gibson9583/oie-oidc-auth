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

import org.junit.jupiter.api.Test;

class OidcConfigTest {

    private static Properties enabled() {
        Properties p = new Properties();
        p.setProperty("enabled", "true");
        p.setProperty("discovery-url", "https://issuer.example/.well-known/openid-configuration");
        p.setProperty("client-id", "client");
        return p;
    }

    @Test
    void parsesPolicy() {
        Properties p = enabled();
        p.setProperty("roles.map", "admins=Administrator,users=User");
        OidcConfig c = OidcConfig.from(p);
        assertTrue(c.jitEnabled());
        assertEquals("Administrator", c.rolesMap().get("admins"));
        assertTrue(c.allowedAlgorithms().contains("RS256"));
        assertEquals(300, c.maxTokenAgeSeconds());
    }

    @Test
    void requiresDiscoveryAndClientIdOnlyWhenEnabled() {
        assertFalse(OidcConfig.from(new Properties()).enabled());   // lenient when disabled

        Properties p = enabled();
        p.remove("client-id");
        assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(p));
    }

    @Test
    void rejectsPlainHttpDiscoveryExceptLocalhost() {
        Properties p = enabled();
        p.setProperty("discovery-url", "http://issuer.example/.well-known/openid-configuration");
        assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(p));

        p.setProperty("discovery-url", "http://localhost:8080/.well-known/openid-configuration");
        assertTrue(OidcConfig.from(p).enabled());   // development exemption
    }

    @Test
    void rejectsAPrefixTheUsernameCharsetCannotCarry() {
        Properties p = enabled();
        p.setProperty("username-prefix", "SSO/");
        assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(p));

        p.setProperty("username-prefix", "sso:");
        assertEquals("sso:", OidcConfig.from(p).usernamePrefix());
    }

    @Test
    void rejectsANonNumericWindow() {
        Properties p = enabled();
        p.setProperty("clock-skew-seconds", "soon");
        assertThrows(NumberFormatException.class, () -> OidcConfig.from(p));
    }

    @Test
    void parsesPairListsPreservingOrderAndSkippingJunk() {
        assertEquals("b", OidcConfig.pairs("a=b, malformed ,c=d").get("a"));
        assertEquals("d", OidcConfig.pairs("a=b,c=d").get("c"));
        assertTrue(OidcConfig.pairs("").isEmpty());
    }
}
