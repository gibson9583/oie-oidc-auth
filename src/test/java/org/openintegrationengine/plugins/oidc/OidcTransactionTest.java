/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.junit.jupiter.api.Test;

/**
 * The sealed cookie that carries a sign-in attempt across the provider round
 * trip. Every guard here has an attack behind it: a seal under another secret
 * (a different engine, or an attacker's), a tampered seal, a stale one replayed
 * after its window, and a verifier that must never be guessable from what the
 * browser sees.
 */
class OidcTransactionTest {

    private static final String SECRET = "a sufficiently long client secret";
    private static final long NOW = 1_700_000_000_000L;

    @Test
    void sealsAndOpensTheSameAttempt() {
        OidcTransaction.Transaction txn = OidcTransaction.fresh("/channels?x=1", NOW);
        String sealed = OidcTransaction.seal(txn, SECRET);

        OidcTransaction.Transaction opened = OidcTransaction.open(sealed, SECRET, NOW + 1000);
        assertEquals(txn, opened);
        assertTrue(sealed.matches("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+"), "cookie-safe: " + sealed);
    }

    @Test
    void aFreshAttemptHasIndependentFullEntropyValues() {
        OidcTransaction.Transaction a = OidcTransaction.fresh("/", NOW);
        OidcTransaction.Transaction b = OidcTransaction.fresh("/", NOW);
        assertNotEquals(a.state(), b.state());
        assertNotEquals(a.nonce(), a.state(), "state and nonce must not be derived from each other");
        assertTrue(a.verifier().length() >= 43 && a.verifier().length() <= 128, "PKCE verifier length");
        assertNotEquals(a.verifier(), b.verifier());
    }

    @Test
    void anotherSecretCannotOpenIt() {
        String sealed = OidcTransaction.seal(OidcTransaction.fresh("/", NOW), SECRET);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> OidcTransaction.open(sealed, "a different client secret", NOW));
        assertEquals("invalid transaction", e.getMessage());
    }

    @Test
    void aTamperedSealIsRefused() {
        String sealed = OidcTransaction.seal(OidcTransaction.fresh("/", NOW), SECRET);
        String[] parts = sealed.split("\\.");
        char first = parts[1].charAt(0);
        String tampered = parts[0] + "." + (first == 'A' ? 'B' : 'A') + parts[1].substring(1);
        assertThrows(IllegalArgumentException.class, () -> OidcTransaction.open(tampered, SECRET, NOW));
        assertThrows(IllegalArgumentException.class, () -> OidcTransaction.open("not.a.seal", SECRET, NOW));
        assertThrows(IllegalArgumentException.class, () -> OidcTransaction.open("", SECRET, NOW));
        assertThrows(IllegalArgumentException.class, () -> OidcTransaction.open(null, SECRET, NOW));
    }

    @Test
    void expiresAfterTenMinutesButToleratesSmallClockDrift() {
        String sealed = OidcTransaction.seal(OidcTransaction.fresh("/", NOW), SECRET);
        OidcTransaction.open(sealed, SECRET, NOW + OidcTransaction.TTL_MILLIS - 1);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> OidcTransaction.open(sealed, SECRET, NOW + OidcTransaction.TTL_MILLIS + 1));
        assertEquals("expired transaction", e.getMessage());
        // A seal from a few seconds "in the future" (another node's clock) opens.
        OidcTransaction.open(sealed, SECRET, NOW - 20_000);
        assertThrows(IllegalArgumentException.class, () -> OidcTransaction.open(sealed, SECRET, NOW - 60_000));
    }

    @Test
    void theReturnPathSurvivesAnythingItMayContain() {
        String path = "/messages/abc?filter=a=b,c\n#frag";
        OidcTransaction.Transaction txn = OidcTransaction.fresh(path, NOW);
        assertEquals(path, OidcTransaction.open(OidcTransaction.seal(txn, SECRET), SECRET, NOW).returnPath());
    }

    @Test
    void theCodeChallengeIsS256OfTheVerifier() throws Exception {
        String verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        String expected = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        assertEquals(expected, OidcTransaction.codeChallenge(verifier));
        // The RFC 7636 appendix B vector.
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", OidcTransaction.codeChallenge(verifier));
    }
}
