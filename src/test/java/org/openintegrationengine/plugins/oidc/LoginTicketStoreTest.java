/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** A ticket is redeemable once, within a minute, and a full store refuses rather than evicts. */
class LoginTicketStoreTest {

    private final LoginTicketStore store = new LoginTicketStore();
    private static final long NOW = 1_700_000_000_000L;

    @Test
    void redeemsExactlyOnce() {
        String id = store.issue("token-1", NOW);
        LoginTicketStore.Ticket ticket = store.redeem(id, NOW + 1000);
        assertEquals("token-1", ticket.token());
        assertNull(store.redeem(id, NOW + 2000), "a second redemption must fail");
        assertNull(store.redeem("no-such-ticket", NOW));
        assertNull(store.redeem(null, NOW));
    }

    @Test
    void idsAreUnguessableAndDistinct() {
        String a = store.issue("t", NOW);
        String b = store.issue("t", NOW);
        assertNotEquals(a, b);
        assertEquals(43, a.length(), "32 random bytes, base64url");
    }

    @Test
    void expiresAfterAMinute() {
        String id = store.issue("token-1", NOW);
        assertNull(store.redeem(id, NOW + LoginTicketStore.TTL_MILLIS + 1));
    }

    @Test
    void refusesRatherThanEvictingWhenFull() {
        String mine = store.issue("mine", NOW);
        for (int i = 0; i < LoginTicketStore.LIMIT; i++) {
            try {
                store.issue("filler-" + i, NOW);
            } catch (SecurityException full) {
                break;
            }
        }
        assertThrows(SecurityException.class, () -> store.issue("one more", NOW));
        assertEquals("mine", store.redeem(mine, NOW + 1).token(), "a genuine ticket is not dropped to make room");
        // Once the flood expires, there is room again.
        store.issue("later", NOW + LoginTicketStore.TTL_MILLIS + 1);
    }
}
