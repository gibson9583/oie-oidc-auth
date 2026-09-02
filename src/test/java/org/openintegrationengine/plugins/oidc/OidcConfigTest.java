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
        p.setProperty("client-secret", "test-client-secret");   // required when enabled: the engine runs the flow
        p.setProperty("web-administrator-url", "https://admin.test");
        p.setProperty("discovery-url", "https://issuer.example/.well-known/openid-configuration");
        p.setProperty("client-id", "client");
        // Mandatory whenever RBAC is on the classpath, which it is here. See
        // requiresADefaultRoleWhenRbacIsInstalled below for why.
        p.setProperty("roles.default", "Viewer");
        return p;
    }

    @Test
    void parsesPolicy() {
        Properties p = enabled();
        p.setProperty("roles.map", "admins=Administrator,users=User");
        OidcConfig c = OidcConfig.from(p);
        assertEquals("Administrator", c.rolesMap().get("admins"));
        assertTrue(c.allowedAlgorithms().contains("RS256"));
        assertEquals(300, c.maxTokenAgeSeconds());
    }

    /**
     * Absent means OFF, matching what OidcConfigLoader seeds. The parser used to
     * default it TRUE, so a stored policy without the key — an upgrade, or
     * hand-written properties — silently provisioned users while the settings
     * tab, which also defaults to "No", showed the feature disabled.
     */
    @Test
    void jitProvisioningIsOffWhenTheKeyIsAbsent() {
        assertFalse(OidcConfig.from(enabled()).jitEnabled());

        Properties on = enabled();
        on.setProperty("jit.enabled", "true");
        assertTrue(OidcConfig.from(on).jitEnabled());
    }

    /**
     * With RBAC installed, claims that resolve to no role would leave the user's
     * existing role in place — so revoking their IdP group would not remove
     * their engine access. Requiring a default makes that state unreachable
     * instead of handling it. RBAC is on this module's test classpath, so the
     * constraint is live here.
     */
    @Test
    void requiresADefaultRoleWhenRbacIsInstalled() {
        assertTrue(RbacRoleAssigner.isInstalled(), "this test asserts the RBAC-present branch");

        Properties p = enabled();
        p.remove("roles.default");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(p));
        assertTrue(e.getMessage().contains("roles.default"), "the error must name the key to set");

        // A blank value is the same omission with extra steps.
        Properties blank = enabled();
        blank.setProperty("roles.default", "   ");
        assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(blank));

        // Disabled configurations stay lenient — nothing is being authorized.
        Properties off = enabled();
        off.setProperty("enabled", "false");
        off.remove("roles.default");
        assertFalse(OidcConfig.from(off).enabled());

        // roles.sync=never returns before the assigner ever reads a default, so
        // no stale role can be kept and demanding an unread value would break a
        // deliberate hand-managed setup.
        Properties unmanaged = enabled();
        unmanaged.setProperty("roles.sync", "never");
        unmanaged.remove("roles.default");
        assertEquals("never", OidcConfig.from(unmanaged).rolesSync());
    }

    /**
     * The value is trimmed, so a stray space cannot pass validation and then
     * fail to match any role at login — which would silently restore the very
     * stale-role behaviour the requirement exists to prevent.
     */
    @Test
    void trimsTheDefaultRole() {
        Properties p = enabled();
        p.setProperty("roles.default", "  Viewer  ");
        assertEquals("Viewer", OidcConfig.from(p).defaultRole());

        Properties whitespaceOnly = enabled();
        whitespaceOnly.setProperty("roles.default", "   ");
        assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(whitespaceOnly));
    }

    /**
     * Shape before semantics: a policy with both a malformed value and a missing
     * required one reports the malformed value first. Either is actionable now
     * that type errors name their key — before the schema they did not, which is
     * why this previously asserted the opposite order.
     */
    @Test
    void reportsAMalformedValueAheadOfAMissingRequiredOne() {
        Properties p = enabled();
        p.remove("client-id");
        p.setProperty("clock-skew-seconds", "abc");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(p));
        assertTrue(e.getMessage().contains("clock-skew-seconds"), e.getMessage());

        // With the types sound, the missing required key is what surfaces.
        Properties typesOk = enabled();
        typesOk.remove("client-id");
        assertTrue(assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(typesOk))
                .getMessage().contains("client-id"));
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

    /**
     * A malformed value names itself and its key. This used to surface as a bare
     * NumberFormatException carrying only the offending text, which told an
     * operator what was unparseable but not which of three numeric keys it came
     * from.
     */
    @Test
    void rejectsANonNumericWindow() {
        Properties p = enabled();
        p.setProperty("clock-skew-seconds", "soon");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(p));
        assertTrue(e.getMessage().contains("clock-skew-seconds"), e.getMessage());
        assertTrue(e.getMessage().contains("soon"), e.getMessage());
    }

    /**
     * Booleans are strict rather than falling back to false the way
     * Boolean.parseBoolean does. "enabled=maybe" silently meaning "off" is the
     * worst reading of a typo in the one key that decides whether SSO runs at
     * all; "jit.enabled=Yes" silently meaning "off" is the second worst.
     */
    @Test
    void rejectsAnUnrecognizedBoolean() {
        Properties p = enabled();
        p.setProperty("jit.enabled", "maybe");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(p));
        assertTrue(e.getMessage().contains("jit.enabled"), e.getMessage());

        // …but the spellings a hand-written or templated config plausibly
        // produces are accepted rather than being a trap.
        for (String yes : new String[] { "true", "TRUE", " yes ", "on", "1" }) {
            Properties on = enabled();
            on.setProperty("jit.enabled", yes);
            assertTrue(OidcConfig.from(on).jitEnabled(), yes);
        }
        for (String no : new String[] { "false", "FALSE", "no", "off", "0" }) {
            Properties off = enabled();
            off.setProperty("jit.enabled", no);
            assertFalse(OidcConfig.from(off).jitEnabled(), no);
        }
    }

    /**
     * roles.sync is the only enum-valued key, and before the schema existed it
     * was the only constrained key with no validation at all: "Never" parsed
     * happily and then meant "reconcile on every login" — the exact opposite of
     * what the operator wrote, silently.
     */
    @Test
    void rejectsAnUnrecognizedRolesSync() {
        for (String bad : new String[] { "Never", "NEVER", "jit_only", "sometimes" }) {
            Properties p = enabled();
            p.setProperty("roles.sync", bad);
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> OidcConfig.from(p), bad);
            assertTrue(e.getMessage().contains("roles.sync"), e.getMessage());
            assertTrue(e.getMessage().contains("always"), "the message must name the accepted values");
        }
        for (String good : new String[] { "always", "jit-only", "never" }) {
            Properties p = enabled();
            p.setProperty("roles.sync", good);
            p.setProperty("roles.default", "Viewer");
            assertEquals(good, OidcConfig.from(p).rolesSync());
        }
    }

    @Test
    void parsesPairListsPreservingOrderAndSkippingJunk() {
        assertEquals("b", OidcConfig.pairs("a=b, malformed ,c=d").get("a"));
        assertEquals("d", OidcConfig.pairs("a=b,c=d").get("c"));
        assertTrue(OidcConfig.pairs("").isEmpty());
    }
}
