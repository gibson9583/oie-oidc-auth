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
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.http.HttpClient;
import java.util.Date;
import java.util.Properties;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.mirth.connect.model.LoginStatus;
import com.nimbusds.jwt.JWTClaimsSet;
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

    /**
     * A plugin whose validator ACCEPTS, so execution reaches the replay cache.
     * Provisioning past that needs the engine's UserController singleton, which
     * is not available here — but the replay check runs first, which is exactly
     * the part under test.
     */
    private static OidcAuthorizationPlugin accepting(OidcTokenValidator validator) throws Exception {
        Properties p = new Properties();
        p.setProperty("enabled", "true");
        p.setProperty("roles.default", "Viewer");
        p.setProperty("discovery-url", "https://issuer.example/.well-known/openid-configuration");
        p.setProperty("client-id", "client");
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin();
        plugin.configure(OidcConfig.from(p), validator);
        return plugin;
    }

    private static JWTClaimsSet validClaims() {
        Date now = new Date();
        return new JWTClaimsSet.Builder().issuer("https://issuer.example").audience("client")
                .subject("subject-1").claim("preferred_username", "jdoe")
                .issueTime(now).expirationTime(new Date(now.getTime() + 300_000)).build();
    }

    /**
     * The replay cache is the engine's ONLY defence against a re-presented ID
     * token — the nonce is checked at the web tier, not here — and nothing
     * proved a second use was refused. The two outcomes are deliberately
     * distinguishable: a reuse says so, everything else is the generic rejection.
     */
    @Test
    void refusesASecondUseOfTheSameToken() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        when(validator.validate(any())).thenReturn(validClaims());
        OidcAuthorizationPlugin plugin = accepting(validator);

        // First use records the token, then fails downstream for want of a
        // UserController — the recording is what matters here.
        LoginStatus first = plugin.authorizeUser("jdoe", "oidc:token-aaa");
        assertEquals(Status.FAIL, first.getStatus());
        assertEquals("SSO sign-in was rejected.", first.getMessage());

        LoginStatus replayed = plugin.authorizeUser("jdoe", "oidc:token-aaa");
        assertEquals(Status.FAIL, replayed.getStatus());
        assertEquals("SSO assertion was already used.", replayed.getMessage(),
                "a re-presented token must be refused as a replay, not as a generic failure");

        // A DIFFERENT token is unaffected — the cache keys on the token, not the
        // user, so one replay must not lock somebody out.
        LoginStatus other = plugin.authorizeUser("jdoe", "oidc:token-bbb");
        assertEquals("SSO sign-in was rejected.", other.getMessage());
    }

    /**
     * The throttle exists because this path bypasses the engine's per-user
     * strike lockout. Enforcement is invisible in the response — every failure
     * returns the same generic message — so assert it where it shows: once the
     * limit is hit, the token is never even handed to the validator.
     */
    @Test
    void stopsCallingTheValidatorOnceAHintIsThrottled() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        when(validator.validate(any())).thenThrow(new SecurityException("bad token"));
        OidcAuthorizationPlugin plugin = accepting(validator);

        for (int i = 0; i < 20; i++) {
            assertEquals(Status.FAIL, plugin.authorizeUser("guessing", "oidc:bad-" + i).getStatus());
        }
        verify(validator, times(20)).validate(any());

        for (int i = 0; i < 5; i++) {
            assertEquals(Status.FAIL, plugin.authorizeUser("guessing", "oidc:bad-extra-" + i).getStatus());
        }
        verify(validator, times(20)).validate(any());   // still 20: the throttle short-circuits

        // The limit is per hint, so a different username is unaffected — a
        // runaway against one name must not deny service to everyone else.
        assertEquals(Status.FAIL, plugin.authorizeUser("someone-else", "oidc:bad-x").getStatus());
        verify(validator, times(21)).validate(any());
    }
}
