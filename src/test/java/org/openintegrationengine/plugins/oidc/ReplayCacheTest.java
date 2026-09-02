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

    @Test
    void refusesATokenPresentedTwice() {
        long now = 1_000_000;
        assertTrue(cache.claim("token", TTL, now), "the first use must be accepted");
        assertFalse(cache.claim("token", TTL, now), "the second use must be refused");
        assertFalse(cache.claim("token", TTL, now + 1000), "and still refused a second later");
        // A different token is unaffected.
        assertTrue(cache.claim("another", TTL, now));
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
        assertTrue(cache.claim("token", TTL, now));
        assertFalse(cache.claim("token", TTL, now + TTL - 1), "still within the token's life — must be refused");
        // Past its expiry the record may go: the token itself no longer validates,
        // so the cache is not what is stopping it.
        assertTrue(cache.claim("token", TTL, now + TTL + 1));
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
        assertTrue(cache.claim("the-captured-token", TTL, now));
        // Fill until the bound bites. It refuses partway through, which is the
        // behaviour under test — so stop there rather than letting the fill fail
        // the test on the guard working.
        for (int i = 0; i <= ReplayCache.LIMIT; i++) {
            try {
                cache.claim("filler-" + i, TTL, now);
            } catch (SecurityException full) {
                break;
            }
        }
        // The captured token must NOT become claimable again. An eviction policy
        // would have dropped its record and this would return true — a replay.
        assertThrows(SecurityException.class, () -> cache.claim("the-captured-token", TTL, now),
                "a full cache must refuse, never forget a record and accept a replay");
        assertThrows(SecurityException.class, () -> cache.claim("anything-else", TTL, now));
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
                cache.claim("old-" + i, TTL, now);
            } catch (SecurityException full) {
                break;
            }
        }
        // Every one of those has since expired, so there is room again.
        long later = now + TTL + 1;
        assertTrue(cache.claim("a-fresh-login", TTL, later),
                "a cache holding only expired records must accept a new token");
    }

    @Test
    void clearForgetsEverything() {
        assertTrue(cache.claim("token", TTL, 1_000_000));
        cache.clear();
        assertTrue(cache.claim("token", TTL, 1_000_000), "a stopped plugin keeps no records");
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
