/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The replay cache's guards, each of which was deletable with the whole suite
 * green while this logic sat inline in {@code authorizeUser}: the capacity
 * bound could be swapped for an eviction and the expiry sweep removed
 * outright, and only the plain "same token twice" case ever failed.
 */
class ReplayCacheTest {

    private static final long TTL = 300_000;   // a five-minute token
    private final ReplayCache cache = new ReplayCache();

    /**
     * A compact-JWS-shaped string. The cache only ever sees tokens the
     * validator accepted, and those are always three segments.
     */
    private static String jws(String payload) {
        return "eyJhbGciOiJFUzI1NiJ9." + payload + ".signature";
    }

    /**
     * The signature segment is not covered by the signature. Several spellings
     * of it verify as the same signature — unused trailing bits, padding, ECDSA's
     * {@code s} versus {@code n−s} — so a key that includes it hands every one
     * of those spellings a fresh record. A token is what was signed: header and
     * payload.
     */
    @Test
    void aTokenIsTheSameTokenWhateverItsSignatureSegmentSays() {
        long now = 1_000_000;
        assertTrue(cache.claim("header.payload.sigA", now + TTL, now));
        assertFalse(cache.claim("header.payload.sigB", now + TTL, now),
                "a re-spelled signature over the same header.payload is a replay");
        assertFalse(cache.claim("header.payload.sigA==", now + TTL, now), "padding is still the same token");
        assertFalse(cache.claim("header.payload.", now + TTL, now), "an empty signature segment too");

        // What the signature covers still distinguishes tokens.
        assertTrue(cache.claim("header.other.sigA", now + TTL, now), "a different payload is a different token");
        assertTrue(cache.claim("other.payload.sigA", now + TTL, now), "a different header is a different token");
    }

    /**
     * A JWT grant is spent by its issuer and jti, whatever token carries them,
     * and that record never collides with a token's signed-content record.
     */
    @Test
    void aGrantIsSpentByItsIssuerAndJti() {
        long now = 1_000_000;
        assertTrue(cache.claimId("https://issuer", "grant-1", now + TTL, now));
        assertFalse(cache.claimId("https://issuer", "grant-1", now + TTL, now), "the same jti is a replay");
        assertTrue(cache.claimId("https://issuer", "grant-2", now + TTL, now), "another jti is another grant");
        assertTrue(cache.claimId("https://other-issuer", "grant-1", now + TTL, now), "jti is unique per issuer");
        assertTrue(cache.claim(jws("grant-1"), now + TTL, now), "content and jti records are separate");
    }

    /**
     * Anything that is not three segments never came out of the validator.
     * There is no honest key to derive from it, so it fails closed rather than
     * being keyed on the whole string — which is the very key that let
     * re-spelled tokens through.
     */
    @Test
    void refusesAStringThatIsNotACompactJws() {
        long now = 1_000_000;
        assertThrows(SecurityException.class, () -> cache.claim("no-dots", now + TTL, now));
        assertThrows(SecurityException.class, () -> cache.claim("header.payload", now + TTL, now));
        assertThrows(SecurityException.class, () -> cache.claim("a.b.c.d.e", now + TTL, now), "JWE is five segments");
    }

    /**
     * The parser trims, so whitespace in front of a token still verifies — and
     * keyed on the raw prefix, {@code " " + token} would be a token never seen.
     * Anything in the signed part that is not canonical base64url is refused
     * outright rather than normalised: a key must be exactly the bytes the
     * signature covers.
     */
    @Test
    void refusesASignedPartThatIsNotCanonicalBase64Url() {
        long now = 1_000_000;
        assertTrue(cache.claim("header.payload.sig", now + TTL, now));
        for (String respelled : new String[] {
                " header.payload.sig", "\theader.payload.sig", "\nheader.payload.sig",
                "header.payload=.sig", "header=.payload.sig", "header.pay load.sig", "header.payload*.sig",
                "\u00a0header.payload.sig", ".payload.sig", "header..sig"}) {
            assertThrows(SecurityException.class, () -> cache.claim(respelled, now + TTL, now),
                    () -> "must refuse " + respelled.replace("\t", "\\t").replace("\n", "\\n"));
        }
    }

    @Test
    void refusesATokenPresentedTwice() {
        long now = 1_000_000;
        assertTrue(cache.claim(jws("token"), now + TTL, now), "the first use must be accepted");
        assertFalse(cache.claim(jws("token"), now + TTL, now), "the second use must be refused");
        assertFalse(cache.claim(jws("token"), now + 1000 + TTL, now + 1000), "and still refused a second later");
        // A different token is unaffected.
        assertTrue(cache.claim(jws("another"), now + TTL, now));
    }

    /**
     * A record outlives the token it describes, and not much longer. Forgetting
     * early would reopen the replay window for a token that is still valid;
     * that is the one mistake here with a security consequence, so the boundary
     * is asserted on both sides.
     */
    @Test
    void remembersForExactlyAsLongAsTheTokenCouldStillBeUsed() {
        long now = 1_000_000;
        assertTrue(cache.claim(jws("token"), now + TTL, now));
        assertFalse(cache.claim(jws("token"), now + TTL - 1 + TTL, now + TTL - 1), "still within the token's life — must be refused");
        // Past its expiry the record may go: the token itself no longer validates,
        // so the cache is not what is stopping it.
        assertTrue(cache.claim(jws("token"), now + TTL + 1 + TTL, now + TTL + 1));
    }

    /**
     * At capacity the cache REFUSES rather than evicts.
     *
     * <p>This is the guard that most looks like a memory bound and is really a
     * security one. Evicting to make room is exactly the move an attacker wants:
     * flood the cache with unrelated tokens, push out the record of the one they
     * captured, and replay it. Refusing costs SSO logins while the flood lasts —
     * local login is unaffected — and costs no replay.</p>
     */
    @Test
    void refusesRatherThanEvictingWhenFull() {
        long now = 1_000_000;
        assertTrue(cache.claim(jws("the-captured-token"), now + TTL, now));
        // Fill until the bound bites. It refuses partway through, which is the
        // behaviour under test — so stop there rather than letting the fill fail
        // the test on the guard working.
        for (int i = 0; i <= ReplayCache.LIMIT; i++) {
            try {
                cache.claim(jws("filler-" + i), now + TTL, now);
            } catch (SecurityException full) {
                break;
            }
        }
        // The captured token must NOT become claimable again. An eviction policy
        // would have dropped its record and this would return true — a replay.
        assertThrows(SecurityException.class, () -> cache.claim(jws("the-captured-token"), now + TTL, now),
                "a full cache must refuse, never forget a record and accept a replay");
        assertThrows(SecurityException.class, () -> cache.claim(jws("anything-else"), now + TTL, now));
    }

    /**
     * Expired records are not what the capacity bound is measuring. Without the
     * sweep, a long-running engine accumulates one entry per login forever and
     * eventually refuses every SSO sign-in on a cache that holds nothing live.
     */
    @Test
    void expiredRecordsDoNotCountTowardCapacity() {
        long now = 1_000_000;
        for (int i = 0; i <= ReplayCache.LIMIT; i++) {
            try {
                cache.claim(jws("old-" + i), now + TTL, now);
            } catch (SecurityException full) {
                break;
            }
        }
        // Every one of those has since expired, so there is room again.
        long later = now + TTL + 1;
        assertTrue(cache.claim(jws("a-fresh-login"), later + TTL, later),
                "a cache holding only expired records must accept a new token");
    }

    /**
     * Hashed, so a heap dump or a debugger does not hand out live bearer tokens.
     */
    @Test
    void storesATruncatedHashRatherThanTheToken() {
        String token = "eyJhbGciOiJSUzI1NiJ9.payload.signature";
        String hashed = ReplayCache.hash(token);
        assertEquals(16, hashed.length());
        assertTrue(hashed.matches("[0-9a-f]{16}"), hashed);
        assertFalse(hashed.contains("payload"));
        assertEquals(hashed, ReplayCache.hash(token), "the same token must hash the same, or nothing is ever a replay");
        assertNotEquals(hashed, ReplayCache.hash(token + "x"));
    }
}
