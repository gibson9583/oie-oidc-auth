/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/** The callback throttle: per forwarded client, in total, and sliding. */
class FlowThrottleTest {

    private static final long NOW = 1_700_000_000_000L;

    @Test
    void aClientGetsItsMinuteAllowanceAndNobodyElsesIsTouched() {
        FlowThrottle throttle = new FlowThrottle();
        for (int i = 0; i < FlowThrottle.PER_CLIENT_PER_MINUTE; i++) {
            throttle.hit("c:203.0.113.9", NOW + i);
        }
        assertThrows(SecurityException.class, () -> throttle.hit("c:203.0.113.9", NOW + 100));
        throttle.hit("c:203.0.113.10", NOW + 100);   // another browser behind the same proxy: unaffected
        throttle.hit("c:203.0.113.9", NOW + 60_001);  // the window slides
    }

    @Test
    void theTotalBoundHoldsHoweverManyClientsAreForged() {
        FlowThrottle throttle = new FlowThrottle();
        // Twelve clients, fifty each: none reaches its own limit; together they reach the total.
        for (int i = 0; i < FlowThrottle.TOTAL_PER_MINUTE; i++) {
            throttle.hit("c:10.0." + (i / 50) + "." + (i % 50), NOW + i);
        }
        assertThrows(SecurityException.class, () -> throttle.hit("c:198.51.100.1", NOW + 1000));
        throttle.hit("c:198.51.100.1", NOW + 60_001);
    }

    @Test
    void theClientIsTheFirstForwardedHopElseThePeer() {
        assertEquals("c:203.0.113.9", FlowThrottle.clientOf("203.0.113.9, 10.0.0.1", "10.0.0.1"));
        assertEquals("c:203.0.113.9", FlowThrottle.clientOf(" 203.0.113.9 ", "10.0.0.1"));
        assertEquals("c:10.0.0.1", FlowThrottle.clientOf(null, "10.0.0.1"));
        assertEquals("c:10.0.0.1", FlowThrottle.clientOf(" , 10.0.0.2", "10.0.0.1"));
    }
}
