/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Refuses an ID token that has already been spent.
 *
 * <p>A valid ID token stays cryptographically valid until it expires, so
 * anything that captures one — a proxy log, a shared browser, an
 * over-broad crash report — can replay it for the remainder of its lifetime.
 * Signature and claim validation cannot see that; only remembering can.</p>
 *
 * <p>Split out of {@code authorizeUser}, which was carrying five separate
 * concerns inline. The reason this is worth its own type is the failure mode:
 * every guard here fails CLOSED, and each does so for a different reason that
 * has to survive editing. Entries expire with the token rather than on a timer
 * of their own, the map is capacity-bounded because entries are attacker-driven,
 * and reaching that bound REFUSES logins instead of evicting — because evicting
 * is precisely how an attacker would make room for a replay.</p>
 */
final class ReplayCache {

    /**
     * Above this, refuse rather than evict. Ten thousand unexpired tokens is
     * already far past any real login rate, so the bound is only reached under
     * attack or gross misconfiguration — and in both cases refusing SSO (local
     * login is unaffected) beats quietly dropping the record that would have
     * caught the replay.
     */
    static final int LIMIT = 10000;

    /** token hash → the instant its record may be forgotten. */
    private final ConcurrentMap<String, Long> seen = new ConcurrentHashMap<>();

    /**
     * Records this token as spent.
     *
     * <p>Returns false — rather than throwing — when the token has already been
     * used, because the caller answers that case with a message of its own
     * ("SSO assertion was already used."). Being told which token was reused is
     * genuinely useful to whoever is signing in; a full cache is not their
     * problem to solve, so that one throws and reaches the generic refusal.</p>
     *
     * @param ttlMillis how long the record must outlive this call — the token's
     *                  own remaining validity, so a record is never dropped
     *                  while the token it describes could still be presented
     * @return true if this is the token's first use
     */
    boolean claim(String token, long ttlMillis, long now) {
        // Sweep first: expired records are not evidence, and clearing them is
        // what keeps the capacity check below measuring live pressure rather
        // than accumulated history.
        seen.entrySet().removeIf(entry -> entry.getValue() < now);
        if (seen.size() > LIMIT) {
            throw new SecurityException("replay cache capacity reached");
        }
        return seen.putIfAbsent(hash(token), now + ttlMillis) == null;
    }

    void clear() {
        seen.clear();
    }

    /**
     * A truncated SHA-256, so a heap dump or a debugger does not hand out live
     * bearer tokens. 64 bits of a cryptographic hash: a collision would let one
     * token block another, which is a refused login, never an accepted one.
     */
    static String hash(String value) {
        try {
            return HexFormat.of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)))
                    .substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
