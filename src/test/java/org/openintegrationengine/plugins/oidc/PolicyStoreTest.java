/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;

/** The engine-backed store: its own group, upsert-then-prune saves, and the slot it empties. */
class PolicyStoreTest {

    /** The configuration table as a map of groups, recording every removal. */
    private static final class Table implements PolicyStore.Table {
        final Map<String, Properties> groups = new HashMap<>();
        final List<String> removedGroups = new ArrayList<>();

        Properties of(String group) {
            return groups.computeIfAbsent(group, g -> new Properties());
        }

        @Override
        public Properties group(String group) {
            Properties stored = groups.get(group);
            if (stored == null) {
                return null;
            }
            Properties copy = new Properties();
            copy.putAll(stored);
            return copy;
        }

        @Override
        public void put(String group, String key, String value) {
            of(group).setProperty(key, value);
        }

        @Override
        public void remove(String group, String key) {
            of(group).remove(key);
        }

        @Override
        public void removeGroup(String group) {
            groups.remove(group);
            removedGroups.add(group);
        }
    }

    @Test
    void theGroupIsNotThePluginsName() {
        // The Extensions page asks for the slot named after the plugin; the
        // policy must live anywhere but there.
        assertNotEquals(OidcAuthorizationPlugin.PLUGIN_POINT, PolicyStore.Engine.GROUP);
    }

    @Test
    void loadsTheGroupAndTreatsAMissingOneAsEmpty() {
        Table table = new Table();
        assertTrue(new PolicyStore.Engine(table).load().isEmpty(), "no group yet");

        table.put(PolicyStore.Engine.GROUP, "client-id", "stored");
        assertEquals("stored", new PolicyStore.Engine(table).load().getProperty("client-id"));
    }

    @Test
    void aSaveUpsertsEveryKeyAndPrunesTheOnesNoLongerPresent() {
        Table table = new Table();
        table.put(PolicyStore.Engine.GROUP, "client-id", "old");
        table.put(PolicyStore.Engine.GROUP, "username-prefix", "gone-after-save");
        PolicyStore.Engine store = new PolicyStore.Engine(table);

        Properties policy = new Properties();
        policy.setProperty("client-id", "new");
        policy.setProperty("enabled", "true");
        store.save(policy);

        Properties stored = table.of(PolicyStore.Engine.GROUP);
        assertEquals("new", stored.getProperty("client-id"));
        assertEquals("true", stored.getProperty("enabled"));
        assertEquals(null, stored.getProperty("username-prefix"), "a key the new policy lacks is removed");
        assertEquals(2, stored.size());
        assertTrue(table.removedGroups.isEmpty(), "a save never drops the whole group");
    }

    @Test
    void clearingTheSlotEmptiesThePluginsOwnGroupAndNothingElse() {
        Table table = new Table();
        table.put(OidcAuthorizationPlugin.PLUGIN_POINT, "client-secret", "left behind by an old build");
        table.put(PolicyStore.Engine.GROUP, "client-id", "keep");

        new PolicyStore.Engine(table).clearPluginSlot();

        assertEquals(List.of(OidcAuthorizationPlugin.PLUGIN_POINT), table.removedGroups);
        assertEquals("keep", table.of(PolicyStore.Engine.GROUP).getProperty("client-id"));
    }
}
