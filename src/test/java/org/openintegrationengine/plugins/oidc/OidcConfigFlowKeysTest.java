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

import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.Test;

/**
 * The keys the engine-run flow added to the policy: the client secret and the
 * web administrator's own address, both required once SSO is on, plus the
 * presentation keys the login card used to take from the web tier's config.
 */
class OidcConfigFlowKeysTest {

    private static Properties enabled() {
        Properties p = new Properties();
        p.setProperty("enabled", "true");
        p.setProperty("discovery-url", "https://issuer.example/.well-known/openid-configuration");
        p.setProperty("client-id", "client");
        p.setProperty("client-secret", "s3cret");
        p.setProperty("web-administrator-url", "https://admin.example");
        p.setProperty("roles.default", "Viewer");
        return p;
    }

    @Test
    void theSecretAndTheWebAdministratorUrlAreRequiredOnceEnabled() {
        Properties noSecret = enabled();
        noSecret.remove("client-secret");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(noSecret)).getMessage().contains("client-secret"));

        Properties noUrl = enabled();
        noUrl.remove("web-administrator-url");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(noUrl)).getMessage().contains("web-administrator-url"));

        // Neither is needed while SSO is off, so a fresh install parses.
        Properties off = enabled();
        off.setProperty("enabled", "false");
        off.remove("client-secret");
        off.remove("web-administrator-url");
        assertFalse(OidcConfig.from(off).enabled());
    }

    @Test
    void theWebAdministratorUrlIsABaseUrlOverHttps() {
        Properties http = enabled();
        http.setProperty("web-administrator-url", "http://admin.example");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(http)).getMessage().contains("HTTPS"));

        Properties local = enabled();
        local.setProperty("web-administrator-url", "http://localhost:3030/");
        assertEquals("http://localhost:3030", OidcConfig.from(local).webAdministratorUrl(), "localhost may be plain, and the trailing slash goes");

        Properties context = enabled();
        context.setProperty("web-administrator-url", "https://engine.example:8443/oie-webadmin/");
        assertEquals("https://engine.example:8443/oie-webadmin", OidcConfig.from(context).webAdministratorUrl(), "a WAR context path is part of the address");

        for (String bad : new String[] { "https://admin.example/?x=1", "https://admin.example/#frag", "https://user:pw@admin.example" }) {
            Properties p = enabled();
            p.setProperty("web-administrator-url", bad);
            assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(p), bad);
        }
    }

    @Test
    void scopesAlwaysLeadWithOpenidAndAcceptEitherSeparator() {
        assertEquals(List.of("openid", "profile", "email"), OidcConfig.scopes("openid profile email"));
        assertEquals(List.of("openid", "profile", "email"), OidcConfig.scopes("profile, email"));
        assertEquals(List.of("openid", "groups"), OidcConfig.scopes("groups,openid"));
        assertEquals(List.of("openid"), OidcConfig.scopes(""));
        assertEquals(List.of("openid", "profile", "email"), OidcConfig.from(enabled()).scopes(), "the default");
    }

    @Test
    void presentationKeysHaveSensibleDefaults() {
        OidcConfig config = OidcConfig.from(enabled());
        assertEquals("SSO", config.providerLabel());
        assertFalse(config.autoRedirect());

        Properties p = enabled();
        p.setProperty("provider-label", "  Acme SSO ");
        p.setProperty("auto-redirect", "yes");
        assertEquals("Acme SSO", OidcConfig.from(p).providerLabel());
        assertTrue(OidcConfig.from(p).autoRedirect());
        p.setProperty("provider-label", "   ");
        assertEquals("SSO", OidcConfig.from(p).providerLabel(), "a blank label falls back rather than drawing an empty button");
    }
}
