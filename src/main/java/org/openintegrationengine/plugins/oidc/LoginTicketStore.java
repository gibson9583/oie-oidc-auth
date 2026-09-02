/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * One-time tickets that carry a validated ID token from the callback to the
 * engine's own login.
 *
 * <p>The callback cannot create the session itself without re-implementing
 * the engine's login servlet — session attributes, the login audit event, and
 * the second factor a multi-factor extension may demand. So it hands the web
 * client a ticket instead, and the client redeems it through
 * {@code POST /users/_login} exactly as a password would be, which runs the
 * whole pipeline unchanged. A ticket is bearer-only for a minute, redeemable
 * once, and the token behind it is validated again on redemption.</p>
 */
final class LoginTicketStore {

    static final long TTL_MILLIS = 60_000;
    /**
     * Above this, refuse rather than evict. Pending sign-ins that never complete
     * are attacker-driven — anyone can start the flow — so a full store refuses
     * new tickets for a minute instead of dropping someone's genuine one.
     */
    static final int LIMIT = 10_000;
    private static final SecureRandom RANDOM = new SecureRandom();

    record Ticket(String token, String returnPath, long expires) {}

    private final ConcurrentMap<String, Ticket> pending = new ConcurrentHashMap<>();

    /** Records a validated token and returns the ticket id that redeems it. */
    String issue(String token, String returnPath, long now) {
        pending.entrySet().removeIf(entry -> entry.getValue().expires() < now);
        if (pending.size() >= LIMIT) {
            throw new SecurityException("too many sign-ins in progress");
        }
        byte[] id = new byte[32];
        RANDOM.nextBytes(id);
        String key = Base64.getUrlEncoder().withoutPadding().encodeToString(id);
        pending.put(key, new Ticket(token, returnPath, now + TTL_MILLIS));
        return key;
    }

    /** The ticket for an id, removed on first use; null if unknown, used, or expired. */
    Ticket redeem(String id, long now) {
        if (id == null) {
            return null;
        }
        Ticket ticket = pending.remove(id);
        return ticket != null && ticket.expires() >= now ? ticket : null;
    }

    int size() {
        return pending.size();
    }

    void clear() {
        pending.clear();
    }
}
