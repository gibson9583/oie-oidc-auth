/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.util.Properties;

import com.mirth.connect.server.controllers.ConfigurationController;

/**
 * Where the policy lives: the extension's OWN group in the engine's
 * configuration table, not the per-plugin properties slot the engine offers
 * every plugin.
 *
 * <p>The slot would have been the obvious choice, and was the first one. But
 * the engine exposes that slot raw — the Extensions page has a "Properties"
 * action that dumps it for any plugin, and a server-configuration export
 * carries it — with no idea which keys are secrets. The settings tab masks the
 * client secret; the slot showed it in the clear to anyone who could view
 * extensions. Keeping the policy in a group of its own means the tab is the
 * only place it exists: the raw view shows nothing for this extension, and no
 * export carries the secret. Same table, same backups, one editor.</p>
 */
interface PolicyStore {

    /** The stored policy; empty when nothing has been saved. */
    Properties load();

    /** Replaces the stored policy with exactly these keys. */
    void save(Properties policy);

    /**
     * Empties the engine's per-plugin properties slot for this extension. Called
     * once at startup after anything found there has been moved into the store,
     * so a policy saved by a build that still used the slot stops being visible
     * raw the first time this build runs.
     */
    void clearPluginSlot();

    /**
     * The four operations the engine's configuration table offers, behind an
     * interface because the engine's controller cannot be instantiated or
     * mocked outside a running engine, and the save logic deserves a test.
     */
    interface Table {
        Properties group(String group);

        void put(String group, String key, String value);

        void remove(String group, String key);

        void removeGroup(String group);
    }

    /** The engine-backed store. */
    final class Engine implements PolicyStore {

        /** A category no plugin is named after, so no generic view asks for it. */
        static final String GROUP = "oidcauth.policy";

        private final Table table;

        Engine(Table table) {
            this.table = table;
        }

        static Engine of(ConfigurationController configuration) {
            return new Engine(new Table() {
                @Override
                public Properties group(String group) {
                    return configuration.getPropertiesForGroup(group);
                }

                @Override
                public void put(String group, String key, String value) {
                    configuration.saveProperty(group, key, value);
                }

                @Override
                public void remove(String group, String key) {
                    configuration.removeProperty(group, key);
                }

                @Override
                public void removeGroup(String group) {
                    configuration.removePropertiesForGroup(group);
                }
            });
        }

        @Override
        public Properties load() {
            Properties stored = table.group(GROUP);
            return stored != null ? stored : new Properties();
        }

        @Override
        public void save(Properties policy) {
            // Upsert every key first, then drop the ones no longer present, so
            // a failure part-way leaves the previous policy in place rather
            // than an empty group.
            for (String key : policy.stringPropertyNames()) {
                table.put(GROUP, key, policy.getProperty(key));
            }
            Properties before = table.group(GROUP);
            if (before != null) {
                for (String key : before.stringPropertyNames()) {
                    if (!policy.containsKey(key)) {
                        table.remove(GROUP, key);
                    }
                }
            }
        }

        @Override
        public void clearPluginSlot() {
            table.removeGroup(OidcAuthorizationPlugin.PLUGIN_POINT);
        }
    }
}
