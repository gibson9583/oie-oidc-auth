/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Bounds how fast the pre-auth callback may be driven — the one step of the
 * sign-in flow that costs the engine an outbound token exchange, and one that
 * anyone can reach: a sealed cookie comes from {@code /start} for the asking,
 * and a callback with a bogus code still makes the engine call the provider.
 * {@code /start} itself (one AES seal, a cached discovery read) and the ticket
 * redemption (one map lookup on a 256-bit id) are not worth a throttle.
 *
 * <p>Per client AND in total. The client is the first {@code X-Forwarded-For}
 * hop when there is one — the web administrator's proxy sets that header
 * trust-aware, and the engine itself already reads it for its audit log —
 * else the remote address. A caller that reaches the engine directly can
 * forge the header, but only to escape its own bucket; the total bound is
 * what limits the exchanges such a caller can cause. Keyed on the remote
 * address alone, every browser behind the proxy shared one bucket: sixty
 * callbacks a minute was the ceiling for the whole deployment, and sixty
 * cheap POSTs from anywhere removed it for everyone.</p>
 */
final class FlowThrottle {

    static final int PER_CLIENT_PER_MINUTE = 60;
    static final int TOTAL_PER_MINUTE = 600;
    private static final long WINDOW_MILLIS = 60_000;
    private static final int SWEEP_THRESHOLD = 1000;
    private static final String TOTAL = "*";

    private final ConcurrentMap<String, Deque<Long>> buckets = new ConcurrentHashMap<>();

    /** The bucket a request is charged to: the first forwarded hop, else the peer. */
    static String clientOf(String forwardedFor, String remoteAddress) {
        if (forwardedFor != null) {
            String first = forwardedFor.split(",", 2)[0].trim();
            if (!first.isEmpty()) {
                return "c:" + first;
            }
        }
        return "c:" + remoteAddress;
    }

    /** Charges one callback to this client; throws once either allowance for the minute is spent. */
    void hit(String client, long now) {
        // Keys are caller-chosen, so the map needs a bound: sweep emptied
        // buckets once it grows. A racing computeIfAbsent can lose one tick to
        // the sweep — acceptable for a throttle.
        if (buckets.size() > SWEEP_THRESHOLD) {
            buckets.entrySet().removeIf(entry -> {
                synchronized (entry.getValue()) {
                    entry.getValue().removeIf(time -> time < now - WINDOW_MILLIS);
                    return entry.getValue().isEmpty();
                }
            });
        }
        charge(client, PER_CLIENT_PER_MINUTE, now);
        charge(TOTAL, TOTAL_PER_MINUTE, now);
    }

    private void charge(String key, int limit, long now) {
        Deque<Long> bucket = buckets.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (bucket) {
            while (!bucket.isEmpty() && bucket.peek() < now - WINDOW_MILLIS) {
                bucket.remove();
            }
            if (bucket.size() >= limit) {
                throw new SecurityException("too many sign-in attempts");
            }
            bucket.add(now);
        }
    }
}
