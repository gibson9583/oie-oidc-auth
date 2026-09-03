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
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
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
import com.mirth.connect.model.LoginStatus.Status;
import com.mirth.connect.model.User;
import com.mirth.connect.server.controllers.UserController;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * The façade contract: null ONLY for unprefixed passwords of accounts the
 * provider does not own (local fall-through keeps engine lockout and
 * break-glass), FAIL — never null — for anything {@code oidc:}-prefixed, only
 * a ticket is a credential, and the kill switch wins over any configuration.
 */
class OidcAuthorizationPluginTest {

    private static final String KILL_SWITCH = "org.openintegrationengine.oidc.disabled";
    private static final String SUBJECT = "https://issuer.example#subject-1";

    @AfterEach
    void clearKillSwitch() {
        System.clearProperty(KILL_SWITCH);
    }

    private static Properties policy() {
        Properties p = new Properties();
        p.setProperty("enabled", "true");
        p.setProperty("client-secret", "test-client-secret");   // required when enabled: the engine runs the flow
        p.setProperty("web-administrator-url", "https://admin.test");
        p.setProperty("roles.default", "Viewer");   // required whenever RBAC is on the classpath
        p.setProperty("discovery-url", "https://issuer.example/.well-known/openid-configuration");
        p.setProperty("client-id", "client");
        return p;
    }

    /** A directory that knows one account, "jdoe" (id 7), bound to the subject or not. */
    private static UserController directory(boolean bound) throws Exception {
        UserController users = mock(UserController.class);
        User jdoe = new User();
        jdoe.setId(7);
        jdoe.setUsername("jdoe");
        when(users.getUser(null, "jdoe")).thenReturn(jdoe);
        when(users.getUserPreference(eq(7), eq(UserProvisioner.BINDING))).thenReturn(bound ? SUBJECT : null);
        return users;
    }

    private static OidcAuthorizationPlugin configured() throws Exception {
        return configured(policy(), directory(false));
    }

    private static OidcAuthorizationPlugin configured(Properties policy, UserController users) throws Exception {
        OidcConfig config = OidcConfig.from(policy);
        // Discovery that always fails: any oidc: login must FAIL closed.
        HttpClient http = mock(HttpClient.class);
        when(http.send(any(), any())).thenThrow(new IOException("IdP unreachable"));
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin();
        plugin.configure(config, new OidcTokenValidator(config, new DiscoveryClient(http)), users);
        return plugin;
    }

    @Test
    void ignoresUnprefixedPasswordsOfAccountsTheProviderDoesNotOwn() throws Exception {
        assertNull(configured().authorizeUser("admin", "hunter2"));
        assertNull(configured().authorizeUser("jdoe", "hunter2"), "jdoe exists but is not bound to a subject");
        assertNull(configured().authorizeUser("admin", null));
    }

    @Test
    void failsClosedWhenUnconfigured() throws Exception {
        LoginStatus status = new OidcAuthorizationPlugin().authorizeUser("oidc", "oidc:ticket:x");
        assertNotNull(status, "an oidc: assertion must never fall through to local auth");
        assertEquals(Status.FAIL, status.getStatus());
    }

    @Test
    void theKillSwitchBeatsAValidConfiguration() throws Exception {
        System.setProperty(KILL_SWITCH, "true");
        LoginStatus status = configured().authorizeUser("oidc", "oidc:ticket:x");
        assertNotNull(status);
        assertEquals(Status.FAIL, status.getStatus());
    }

    /* ---- the secret at rest ----------------------------------------------- */

    /** A reversible stand-in for the engine's encryptor, with a switch to break decryption. */
    private static final class FakeCipher implements SecretCipher {
        boolean broken;

        @Override
        public String encrypt(String plain) {
            return new StringBuilder(plain).reverse().toString();
        }

        @Override
        public String decrypt(String ciphertext) throws Exception {
            if (broken) {
                throw new Exception("wrong key");
            }
            return new StringBuilder(ciphertext).reverse().toString();
        }
    }

    /** The engine's slot, as a plugin sees it: whatever was last saved. */
    private static final class Slot implements OidcAuthorizationPlugin.PolicySlot {
        Properties saved;

        @Override
        public void save(Properties policy) {
            saved = new Properties();
            saved.putAll(policy);
        }
    }

    private static Properties sealedPolicy(FakeCipher cipher) throws Exception {
        Properties p = policy();
        p.setProperty("client-secret", cipher.seal("test-client-secret"));
        return p;
    }

    @Test
    void theSlotIsSeededWithEveryDefault() {
        // The engine's native lifecycle: defaults seeded on install, merged on
        // upgrade, pushed back at startup. Exports and restores carry the slot.
        assertEquals(PolicySchema.KEYS.size(), new OidcAuthorizationPlugin().getDefaultProperties().size());
    }

    @Test
    void aSavedSecretIsStoredSealedAndAppliedInTheClear() throws Exception {
        FakeCipher cipher = new FakeCipher();
        Slot slot = new Slot();
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin(() -> cipher, slot);
        plugin.init(OidcConfigLoader.defaults());

        OidcConfigLoader.saveAndApply(policy());   // the tab sends the secret in the clear

        String stored = slot.saved.getProperty("client-secret");
        assertEquals(true, SecretCipher.sealed(stored), stored);
        assertEquals(false, stored.contains("test-client-secret"), "the slot never holds the plain secret");
        assertEquals("test-client-secret", OidcAuthorizationPlugin.currentConfig().clientSecret(), "the flow gets the plain one");
        assertEquals(stored, OidcAuthorizationPlugin.currentProperties().getProperty("client-secret"), "the GET sees the sealed one, and masks it");
        assertEquals("client", slot.saved.getProperty("client-id"), "everything else is stored as is");
    }

    @Test
    void aSealedSecretOpensAtStartupAndOnAnEngineSlotWrite() throws Exception {
        FakeCipher cipher = new FakeCipher();
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin(() -> cipher, new Slot());

        plugin.init(sealedPolicy(cipher));
        assertEquals("test-client-secret", OidcAuthorizationPlugin.currentConfig().clientSecret());

        Properties rewritten = sealedPolicy(cipher);
        rewritten.setProperty("provider-label", "Renamed");
        plugin.update(rewritten);   // a configuration restore, or the generic properties endpoint
        assertEquals("Renamed", OidcAuthorizationPlugin.currentConfig().providerLabel());
    }

    @Test
    void aSecretWrittenInTheClearIsRefusedNotUsed() {
        // A raw write to the slot, or a pre-encryption build's value: fail
        // closed, and say what to do.
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin(() -> new FakeCipher(), new Slot());

        plugin.init(policy());   // client-secret in the clear

        assertNull(OidcAuthorizationPlugin.currentConfig());
        assertEquals(true, String.valueOf(OidcAuthorizationPlugin.currentError()).contains("stored unencrypted"),
                OidcAuthorizationPlugin.currentError());
    }

    @Test
    void aSecretThatDoesNotDecryptFailsClosed() throws Exception {
        FakeCipher cipher = new FakeCipher();
        Properties sealed = sealedPolicy(cipher);
        cipher.broken = true;   // another engine's key, or a tampered value
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin(() -> cipher, new Slot());

        plugin.init(sealed);

        assertNull(OidcAuthorizationPlugin.currentConfig());
        assertEquals(true, String.valueOf(OidcAuthorizationPlugin.currentError()).contains("could not be decrypted"),
                OidcAuthorizationPlugin.currentError());
    }

    @Test
    void anOperatorPinSuppliesTheSecretInTheClearOverTheStoredOne() throws Exception {
        FakeCipher cipher = new FakeCipher();
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin(() -> cipher, new Slot());
        System.setProperty("org.openintegrationengine.oidc.client-secret", "pinned-secret");
        try {
            plugin.init(sealedPolicy(cipher));
            assertEquals("pinned-secret", OidcAuthorizationPlugin.currentConfig().clientSecret());
        } finally {
            System.clearProperty("org.openintegrationengine.oidc.client-secret");
        }
    }

    /**
     * The pin is the operator's rescue for a stored secret that no longer
     * opens, so it must win BEFORE the stored value is judged: a plain-text
     * leftover or a foreign-key value under a pin is a working policy.
     */
    @Test
    void aPinRescuesAStoredSecretThatCannotBeOpened() throws Exception {
        FakeCipher cipher = new FakeCipher();
        System.setProperty("org.openintegrationengine.oidc.client-secret", "pinned-secret");
        try {
            OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin(() -> cipher, new Slot());
            plugin.init(policy());   // stored in the clear
            assertEquals("pinned-secret", OidcAuthorizationPlugin.currentConfig().clientSecret());
            assertNull(OidcAuthorizationPlugin.currentError());

            Properties foreign = sealedPolicy(cipher);
            cipher.broken = true;    // sealed under another engine's key
            plugin.init(foreign);
            assertEquals("pinned-secret", OidcAuthorizationPlugin.currentConfig().clientSecret());
            assertNull(OidcAuthorizationPlugin.currentError());
        } finally {
            System.clearProperty("org.openintegrationengine.oidc.client-secret");
        }
    }

    /**
     * A save whose secret field came back as the mask carries the STORED,
     * already-sealed value (the servlet's merge keeps it). Sealing must leave
     * it exactly as it is: sealing twice would store a value that opens to
     * ciphertext, and every sign-in would present the wrong secret.
     */
    @Test
    void aSaveCarryingAnAlreadySealedSecretStoresItUnchanged() throws Exception {
        FakeCipher cipher = new FakeCipher();
        Slot slot = new Slot();
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin(() -> cipher, slot);
        Properties stored = sealedPolicy(cipher);
        plugin.init(stored);

        Properties resave = new Properties();
        resave.putAll(stored);
        resave.setProperty("provider-label", "Renamed");   // the only edit; the secret field showed the mask
        OidcConfigLoader.saveAndApply(resave);

        assertEquals(stored.getProperty("client-secret"), slot.saved.getProperty("client-secret"), "sealed once, not twice");
        assertEquals("test-client-secret", OidcAuthorizationPlugin.currentConfig().clientSecret());
        assertEquals("Renamed", OidcAuthorizationPlugin.currentConfig().providerLabel());
    }

    @Test
    void anEmptySecretNeedsNoSealAndADisabledPolicyStillLoads() {
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin(() -> new FakeCipher(), new Slot());
        plugin.init(OidcConfigLoader.defaults());   // fresh install: enabled=false, secret ""
        assertEquals(false, OidcAuthorizationPlugin.currentConfig().enabled());
        assertNull(OidcAuthorizationPlugin.currentError());
    }

    /* ---- only a ticket is a credential --------------------------------- */

    /**
     * A plugin whose validator ACCEPTS, so execution reaches the replay cache
     * and provisioning. The directory knows nobody and JIT is off, so
     * provisioning refuses with the generic message — the checks before it are
     * what these tests are about.
     */
    private static OidcAuthorizationPlugin accepting(OidcTokenValidator validator) throws Exception {
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin();
        plugin.configure(OidcConfig.from(policy()), validator, mock(UserController.class));
        return plugin;
    }

    private static JWTClaimsSet validClaims() {
        Date now = new Date();
        return new JWTClaimsSet.Builder().issuer("https://issuer.example").audience("client")
                .subject("subject-1").claim("preferred_username", "jdoe")
                .issueTime(now).expirationTime(new Date(now.getTime() + 300_000)).build();
    }

    private static String ticketFor(OidcAuthorizationPlugin plugin, String token) {
        return "oidc:ticket:" + plugin.tickets().issue(token, System.currentTimeMillis());
    }

    /**
     * The engine's callback is the only place a token is validated with its
     * nonce, and a ticket is the only thing it hands out. A bare ID token
     * presented to the login — from a provider log, another application on the
     * same client, some other flow — never touched that callback, so it is
     * refused without being looked at: the validator is not consulted, and
     * nothing about the string matters.
     */
    @Test
    void aBareIdTokenIsRefusedWithoutBeingExamined() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        when(validator.validate(any())).thenReturn(validClaims());
        OidcAuthorizationPlugin plugin = accepting(validator);

        LoginStatus status = plugin.authorizeUser("oidc", "oidc:eyJhbGciOiJSUzI1NiJ9.e30.sig");
        assertNotNull(status);
        assertEquals(Status.FAIL, status.getStatus());
        assertEquals("SSO sign-in was rejected.", status.getMessage());
        verify(validator, never()).validate(any());
    }

    @Test
    void anUnknownTicketIsRefusedWithoutTheValidator() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        OidcAuthorizationPlugin plugin = accepting(validator);

        LoginStatus status = plugin.authorizeUser("oidc", "oidc:ticket:no-such-ticket");
        assertEquals(Status.FAIL, status.getStatus());
        assertEquals("SSO sign-in expired or was already used. Try again.", status.getMessage());
        verify(validator, never()).validate(any());
    }

    /**
     * A ticket redeems once. Behind it, the replay cache still refuses the
     * TOKEN a second time — the backstop for the day two tickets are issued for
     * one token. The two outcomes are deliberately distinguishable.
     */
    @Test
    void aTicketRedeemsOnceAndTheTokenBehindItIsNeverAcceptedTwice() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        when(validator.validate(any())).thenReturn(validClaims());
        OidcAuthorizationPlugin plugin = accepting(validator);

        String first = ticketFor(plugin, "token-aaa");
        LoginStatus redeemed = plugin.authorizeUser("oidc", first);
        assertEquals(Status.FAIL, redeemed.getStatus());
        assertEquals("SSO sign-in was rejected.", redeemed.getMessage(), "past the token checks; refused by provisioning");
        verify(validator, times(1)).validate("token-aaa");

        assertEquals("SSO sign-in expired or was already used. Try again.", plugin.authorizeUser("oidc", first).getMessage());

        LoginStatus replayed = plugin.authorizeUser("oidc", ticketFor(plugin, "token-aaa"));
        assertEquals("SSO assertion was already used.", replayed.getMessage(),
                "a second ticket for the same token must be refused as a replay");

        // A DIFFERENT token is unaffected — the cache keys on the token, not the
        // user, so one replay must not lock somebody out.
        assertEquals("SSO sign-in was rejected.", plugin.authorizeUser("oidc", ticketFor(plugin, "token-bbb")).getMessage());
    }

    /**
     * The validator accepts a token while {@code iat >= now - (maxAge + skew)},
     * so a replay record must live that long from its use. Kept for maxAge
     * alone, the final skew seconds of every token's life were replayable.
     */
    @Test
    void aReplayRecordOutlivesTheTokensAcceptanceWindow() {
        Properties p = policy();
        p.setProperty("max-token-age-seconds", "300");
        p.setProperty("clock-skew-seconds", "60");
        assertEquals(360_000L, OidcAuthorizationPlugin.replayTtlMillis(OidcConfig.from(p)));
        p.setProperty("clock-skew-seconds", "0");
        assertEquals(300_000L, OidcAuthorizationPlugin.replayTtlMillis(OidcConfig.from(p)));
    }

    /* ---- SSO-managed accounts have no local way in ----------------------- */

    /**
     * An account bound to a provider subject belongs to the provider. A local
     * password set on it — by the user through their own profile, by an
     * administrator, by the API — must not become a way in that outlives the
     * provider removing them.
     */
    @Test
    void anSsoManagedAccountCannotSignInWithALocalPassword() throws Exception {
        LoginStatus status = configured(policy(), directory(true)).authorizeUser("jdoe", "hunter2");
        assertNotNull(status, "a bound account must not fall through to local auth");
        assertEquals(Status.FAIL, status.getStatus());
        assertEquals(OidcAuthorizationPlugin.SSO_MANAGED_MESSAGE, status.getMessage());
    }

    @Test
    void aLinkedAccountKeepsItsLocalPasswordByTheOperatorsDecision() throws Exception {
        Properties p = policy();
        p.setProperty("linked-accounts", "jdoe=" + SUBJECT);
        assertNull(configured(p, directory(true)).authorizeUser("jdoe", "hunter2"));
    }

    @Test
    void localPasswordsWorkForEveryoneWhileSsoIsOff() throws Exception {
        Properties off = policy();
        off.setProperty("enabled", "false");
        assertNull(configured(off, directory(true)).authorizeUser("jdoe", "hunter2"), "policy disabled");

        System.setProperty(KILL_SWITCH, "true");
        assertNull(configured(policy(), directory(true)).authorizeUser("jdoe", "hunter2"), "emergency switch thrown");
    }

    @Test
    void aFailedBindingLookupNeverLocksAnyoneOutOfLocalSignIn() throws Exception {
        UserController broken = mock(UserController.class);
        when(broken.getUser(any(), any())).thenThrow(new RuntimeException("database away"));
        assertNull(configured(policy(), broken).authorizeUser("jdoe", "hunter2"));
        verify(broken, never()).getUserPreference(anyInt(), any());
    }
}
