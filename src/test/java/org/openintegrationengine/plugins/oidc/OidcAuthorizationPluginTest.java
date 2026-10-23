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
import static org.mockito.Mockito.verifyNoInteractions;
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
 * break-glass), FAIL — never null — for anything {@code oidc:}-prefixed. A
 * ticket and an {@code oidc:jwt:} token are the credentials, and the kill
 * switch wins over any configuration.
 */
class OidcAuthorizationPluginTest {

    private static final String KILL_SWITCH = "org.openintegrationengine.oidc.disabled";
    private static final String SUBJECT = "https://issuer.example#subject-1";
    /**
     * A start time well before any test token, for tests about something other
     * than the startup cutoff: a jwt: token issued in the first skew seconds
     * of an instance's life is refused.
     */
    private static final long LONG_AGO = 0L;

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

    /* ---- ticket and jwt are the credentials ---------------------------- */

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

    /** The policy with jwt: on, addressed to this engine. */
    private static Properties jwtPolicy() {
        Properties p = policy();
        p.setProperty("jwt.enabled", "true");
        p.setProperty("jwt.audience", "https://engine.example");
        return p;
    }

    /** A plugin with jwt: on and its replay memory begun long ago. */
    private static OidcAuthorizationPlugin jwtPlugin(OidcTokenValidator validator, UserController users) {
        Properties p = jwtPolicy();
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin();
        plugin.configure(OidcConfig.from(p), validator, users);
        plugin.startedAt(LONG_AGO);
        return plugin;
    }

    private static JWTClaimsSet validClaims() {
        return claimsIssuedAt(new Date());
    }

    private static JWTClaimsSet claimsIssuedAt(Date issued) {
        return new JWTClaimsSet.Builder().issuer("https://issuer.example").audience("client")
                .subject("subject-1").claim("preferred_username", "jdoe")
                .issueTime(issued).expirationTime(new Date(issued.getTime() + 300_000)).build();
    }

    /**
     * Grant claims for a test token. The jti is the token's middle segment,
     * so {@code header.aaa.sigA} and {@code header.aaa.sigB} are one grant
     * and {@code header.bbb.sig} another.
     */
    private static JWTClaimsSet grantFor(String token, Date issued) {
        String[] parts = token.trim().split("\\.");
        Date expires = new Date(issued.getTime() + 120_000);
        return new JWTClaimsSet.Builder().issuer("https://issuer.example").audience("https://engine.example")
                .subject("subject-1").claim("preferred_username", "jdoe").jwtID(parts.length > 1 ? parts[1] : token)
                .issueTime(issued).expirationTime(expires).build();
    }

    /** Both validators accept: an ID token as validClaims(), a grant as grantFor(token). */
    private static void acceptAll(OidcTokenValidator validator) throws Exception {
        when(validator.validate(any())).thenReturn(validClaims());
        when(validator.validateGrant(any())).thenAnswer(call -> grantFor(call.getArgument(0), new Date()));
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

        LoginStatus status = plugin.authorizeUser("jdoe", "oidc:eyJhbGciOiJSUzI1NiJ9.e30.sig");
        assertNotNull(status);
        assertEquals(Status.FAIL, status.getStatus());
        assertEquals("SSO sign-in was rejected.", status.getMessage());
        verify(validator, never()).validate(any());
    }

    /**
     * {@code oidc:jwt:} is off unless the policy turns it on. A presentation
     * while it is off is refused unread — the validator is not consulted — and
     * a ticket for the browser flow still proceeds.
     */
    @Test
    void aDirectJwtIsRefusedWhenTheFlagIsOffAndATicketStillProceeds() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        when(validator.validate(any())).thenReturn(validClaims());
        OidcAuthorizationPlugin plugin = accepting(validator);

        LoginStatus jwt = plugin.authorizeUser("jdoe", "oidc:jwt:header.aaa.sig");
        assertEquals(Status.FAIL, jwt.getStatus());
        assertEquals("SSO sign-in was rejected.", jwt.getMessage());
        verify(validator, never()).validateGrant(any());

        LoginStatus ticket = plugin.authorizeUser("jdoe", ticketFor(plugin, "header.bbb.sig"));
        assertEquals("SSO sign-in was rejected.", ticket.getMessage(), "past the token checks; refused by provisioning");
        verify(validator, times(1)).validate("header.bbb.sig");
    }

    /**
     * {@code oidc:jwt:} is a JWT grant the configured provider minted for this
     * engine. The grant validator accepts it, the account path runs, and the
     * returned username is the session. A second presentation is a replay.
     * The policy must opt in; the default is off.
     */
    @Test
    void aGrantPresentedAsJwtStartsASessionAndCannotBeReplayed() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        when(validator.validateGrant("header.aaa.sig")).thenReturn(grantFor("header.aaa.sig", new Date()));
        OidcAuthorizationPlugin plugin = jwtPlugin(validator, directory(true));

        LoginStatus status = plugin.authorizeUser("jdoe", "oidc:jwt:header.aaa.sig");
        assertEquals(Status.SUCCESS, status.getStatus());
        assertEquals("jdoe", status.getUpdatedUsername());
        verify(validator, times(1)).validateGrant("header.aaa.sig");
        verify(validator, never()).validate(any());

        assertEquals("SSO assertion was already used.", plugin.authorizeUser("jdoe", "oidc:jwt:header.aaa.sig").getMessage());
        verify(validator, times(2)).validateGrant("header.aaa.sig");
    }

    /**
     * A spent grant is spent by its jti, so no other spelling or signature of
     * it signs in again: a re-spelled signature segment, padding, whitespace
     * the parser trims, or the same jti re-signed with another payload.
     */
    @Test
    void aSpentGrantCannotSignInAgainUnderAnySpelling() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        acceptAll(validator);
        OidcAuthorizationPlugin plugin = jwtPlugin(validator, directory(true));

        assertEquals(Status.SUCCESS, plugin.authorizeUser("jdoe", "oidc:jwt:header.aaa.sigA").getStatus());

        for (String spelling : new String[] { "header.aaa.sigB", "header.aaa.sigA==", " header.aaa.sigA" }) {
            assertEquals("SSO assertion was already used.",
                    plugin.authorizeUser("jdoe", "oidc:jwt:" + spelling).getMessage(), spelling);
        }
        when(validator.validateGrant("other.payload.sig")).thenReturn(grantFor("header.aaa.sig", new Date()));
        assertEquals("SSO assertion was already used.",
                plugin.authorizeUser("jdoe", "oidc:jwt:other.payload.sig").getMessage(),
                "a different token carrying a spent jti is the spent grant");

        assertEquals(Status.SUCCESS, plugin.authorizeUser("jdoe", "oidc:jwt:header.bbb.sigA").getStatus(),
                "a different jti is a different grant");
    }

    /**
     * An ID token behind a ticket has no jti to rely on, so it is spent by
     * what was signed: its signature segment re-spelled is still the spent
     * token. The validator accepts every spelling (ECDSA's {@code n−s}, unused
     * base64 bits, padding), so the record has to recognise them.
     */
    @Test
    void aSpentTicketTokenWithAReSpelledSignatureCannotSignInAgain() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        acceptAll(validator);
        OidcAuthorizationPlugin plugin = jwtPlugin(validator, directory(true));

        assertEquals(Status.SUCCESS, plugin.authorizeUser("jdoe", ticketFor(plugin, "header.aaa.sigA")).getStatus());
        assertEquals("SSO assertion was already used.",
                plugin.authorizeUser("jdoe", ticketFor(plugin, "header.aaa.sigB")).getMessage());
        assertEquals("SSO assertion was already used.",
                plugin.authorizeUser("jdoe", ticketFor(plugin, "header.aaa.sigA==")).getMessage());
        assertEquals(Status.SUCCESS, plugin.authorizeUser("jdoe", ticketFor(plugin, "header.bbb.sigA")).getStatus(),
                "a different payload is a different token");
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

        String first = ticketFor(plugin, "header.aaa.sig");
        LoginStatus redeemed = plugin.authorizeUser("jdoe", first);
        assertEquals(Status.FAIL, redeemed.getStatus());
        assertEquals("SSO sign-in was rejected.", redeemed.getMessage(), "past the token checks; refused by provisioning");
        verify(validator, times(1)).validate("header.aaa.sig");

        assertEquals("SSO sign-in expired or was already used. Try again.", plugin.authorizeUser("jdoe", first).getMessage());

        LoginStatus replayed = plugin.authorizeUser("jdoe", ticketFor(plugin, "header.aaa.sig"));
        assertEquals("SSO assertion was already used.", replayed.getMessage(),
                "a second ticket for the same token must be refused as a replay");

        // A DIFFERENT token is unaffected — the cache keys on the token, not the
        // user, so one replay must not lock somebody out.
        assertEquals("SSO sign-in was rejected.", plugin.authorizeUser("jdoe", ticketFor(plugin, "header.bbb.sig")).getMessage());
    }

    /**
     * A jwt: credential is checked as a grant (this engine's audience, a jti,
     * a short lifetime) and never as an ID token; a ticket's token the other
     * way round. A refused grant is not spent and touches no account.
     */
    @Test
    void aJwtIsCheckedAsAGrantAndATicketAsAnIdToken() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        when(validator.validate(any())).thenReturn(validClaims());
        when(validator.validateGrant(any())).thenThrow(new SecurityException("audience rejected"));
        UserController users = directory(true);
        OidcAuthorizationPlugin plugin = jwtPlugin(validator, users);

        LoginStatus jwt = plugin.authorizeUser("jdoe", "oidc:jwt:header.aaa.sig");
        assertEquals(Status.FAIL, jwt.getStatus());
        assertEquals("SSO sign-in was rejected.", jwt.getMessage());
        verifyNoInteractions(users);
        verify(validator, never()).validate(any());

        LoginStatus ticket = plugin.authorizeUser("jdoe", ticketFor(plugin, "header.bbb.sig"));
        assertEquals(Status.SUCCESS, ticket.getStatus());
        verify(validator, times(1)).validateGrant(any());
        verify(validator, times(1)).validate("header.bbb.sig");
    }

    /* ---- the submitted username must be the token's user ----------------- */

    /**
     * The engine's HTTP Basic path runs a request as the username it was SENT,
     * never the one this plugin returns. So a valid ticket from one's own
     * sign-in, presented as {@code admin:oidc:ticket:<id>}, acted as admin.
     * Refused here — before the directory is touched, so nothing is
     * provisioned and no role moves — and the token stays spent.
     */
    @Test
    void aTicketPresentedUnderAnotherAccountsNameIsRefused() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        when(validator.validate(any())).thenReturn(validClaims());
        UserController users = directory(true);
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin();
        plugin.configure(OidcConfig.from(policy()), validator, users);

        LoginStatus status = plugin.authorizeUser("admin", ticketFor(plugin, "header.aaa.sig"));
        assertEquals(Status.FAIL, status.getStatus());
        assertEquals("SSO sign-in was rejected.", status.getMessage());
        verifyNoInteractions(users);

        assertEquals("SSO assertion was already used.", plugin.authorizeUser("jdoe", ticketFor(plugin, "header.aaa.sig")).getMessage(),
                "a refused presentation still spends the token");
    }

    @Test
    void aJwtPresentedUnderAnotherAccountsNameIsRefused() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        acceptAll(validator);
        UserController users = directory(true);
        OidcAuthorizationPlugin plugin = jwtPlugin(validator, users);

        LoginStatus status = plugin.authorizeUser("admin", "oidc:jwt:header.aaa.sig");
        assertEquals(Status.FAIL, status.getStatus());
        assertEquals("SSO sign-in was rejected.", status.getMessage());
        verifyNoInteractions(users);

        assertEquals(Status.SUCCESS, plugin.authorizeUser("jdoe", "oidc:jwt:header.bbb.sig").getStatus(),
                "the token's own user still signs in");
    }

    /**
     * A client that sends no username — an old web client, a hand-built
     * request — does not fall back to the token's user. The name is part of
     * the credential: without it the login is refused, before the directory is
     * touched, for a ticket and a jwt: token alike.
     */
    @Test
    void aMissingUsernameIsRefusedRatherThanFilledIn() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        acceptAll(validator);
        UserController users = directory(true);
        OidcAuthorizationPlugin plugin = jwtPlugin(validator, users);

        String[] missing = { null, "", " " };
        for (int i = 0; i < missing.length; i++) {
            LoginStatus ticket = plugin.authorizeUser(missing[i], ticketFor(plugin, "header.ticket" + i + ".sig"));
            assertEquals(Status.FAIL, ticket.getStatus(), "ticket with username [" + missing[i] + "]");
            assertEquals("SSO sign-in was rejected.", ticket.getMessage());
            LoginStatus jwt = plugin.authorizeUser(missing[i], "oidc:jwt:header.jwt" + i + ".sig");
            assertEquals(Status.FAIL, jwt.getStatus(), "jwt with username [" + missing[i] + "]");
            assertEquals("SSO sign-in was rejected.", jwt.getMessage());
        }
        verifyNoInteractions(users);
    }

    /**
     * No placeholder is exempt: an engine user can be named {@code oidc}, and
     * an IdP claim can produce that name through JIT. Nor a case variant: the
     * mapped name is already lower-cased, and a looser match could let an
     * engine with case-insensitive lookups resolve a different account.
     */
    @Test
    void neitherAPlaceholderNorACaseVariantOfTheUsernameIsAccepted() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        acceptAll(validator);
        OidcAuthorizationPlugin plugin = jwtPlugin(validator, directory(true));

        assertEquals(Status.FAIL, plugin.authorizeUser("oidc", "oidc:jwt:header.aaa.sig").getStatus());
        assertEquals(Status.FAIL, plugin.authorizeUser("JDoe", "oidc:jwt:header.bbb.sig").getStatus());
        assertEquals(Status.FAIL, plugin.authorizeUser(null, "oidc:jwt:header.ccc.sig").getStatus());
    }

    /* ---- a restart does not bring spent tokens back ---------------------- */

    /**
     * The replay cache lives in memory and starts empty with each instance, so
     * a jwt: token issued before the instance began may have been spent on an
     * earlier run. It is refused, and so is one issued within the clock skew
     * after the start, since a provider clock running behind can stamp a
     * pre-restart token that late. From startedAt + skew on, tokens are
     * accepted.
     */
    @Test
    void aJwtIssuedBeforeThisInstanceCouldRememberItIsRefused() throws Exception {
        long started = 1_700_000_000_000L;
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        for (String token : new String[] { "header.before.sig", "header.within.sig", "header.after.sig" }) {
            long offset = token.contains("before") ? -10_000 : token.contains("within") ? 59_000 : 60_000;
            when(validator.validateGrant(token)).thenReturn(grantFor(token, new Date(started + offset)));
        }
        Properties p = jwtPolicy();
        p.setProperty("clock-skew-seconds", "60");
        UserController users = directory(true);
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin();
        plugin.configure(OidcConfig.from(p), validator, users);
        plugin.startedAt(started);

        for (String token : new String[] { "header.before.sig", "header.within.sig" }) {
            LoginStatus status = plugin.authorizeUser("jdoe", "oidc:jwt:" + token);
            assertEquals(Status.FAIL, status.getStatus(), token);
            assertEquals("SSO sign-in was rejected.", status.getMessage(), token);
        }
        verifyNoInteractions(users);

        assertEquals(Status.SUCCESS, plugin.authorizeUser("jdoe", "oidc:jwt:header.after.sig").getStatus(),
                "a token issued at startedAt + skew is accepted");
    }

    /**
     * A ticket cannot carry a spent token: the callback got the token behind it
     * from the provider's token endpoint by redeeming a single-use code, and
     * tickets do not survive a restart. So the cutoff does not apply, and a
     * provider clock running behind does not refuse real browser sign-ins in
     * the first minute after a restart.
     */
    @Test
    void aTicketIsNotSubjectToTheStartupCutoff() throws Exception {
        long started = System.currentTimeMillis();
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        when(validator.validate(any())).thenReturn(claimsIssuedAt(new Date(started - 10_000)));
        OidcAuthorizationPlugin plugin = new OidcAuthorizationPlugin();
        plugin.configure(OidcConfig.from(policy()), validator, directory(true));
        plugin.startedAt(started);

        LoginStatus status = plugin.authorizeUser("jdoe", ticketFor(plugin, "header.aaa.sig"));
        assertEquals(Status.SUCCESS, status.getStatus());
        assertEquals("jdoe", status.getUpdatedUsername());
    }

    /**
     * Stopping the plugin drops outstanding tickets, but not the record of
     * spent tokens: forgetting those is what would let one sign in again.
     */
    @Test
    void aSpentTokenStaysSpentAcrossStop() throws Exception {
        OidcTokenValidator validator = mock(OidcTokenValidator.class);
        acceptAll(validator);
        OidcAuthorizationPlugin plugin = jwtPlugin(validator, directory(true));

        assertEquals(Status.SUCCESS, plugin.authorizeUser("jdoe", "oidc:jwt:header.aaa.sig").getStatus());
        String pending = ticketFor(plugin, "header.bbb.sig");
        plugin.stop();

        assertEquals("SSO assertion was already used.", plugin.authorizeUser("jdoe", "oidc:jwt:header.aaa.sig").getMessage());
        assertEquals("SSO sign-in expired or was already used. Try again.", plugin.authorizeUser("jdoe", pending).getMessage(),
                "stop() still drops outstanding tickets");
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
