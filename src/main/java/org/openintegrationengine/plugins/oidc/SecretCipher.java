/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.util.Properties;

import com.mirth.commons.encryption.Encryptor;
import com.mirth.connect.server.controllers.ConfigurationController;

/**
 * The client secret at rest. It is stored in the engine's per-plugin
 * properties slot with the rest of the policy — the slot is what
 * configuration exports carry and restores put back — but encrypted with the
 * engine's own key, so the raw views of that slot (the Extensions page's
 * Properties action, an export) show ciphertext, and a value that was not
 * sealed by this engine is refused rather than used.
 *
 * <p>Sealed values carry {@link #MARK} so they can be told from a secret
 * written in the clear — by a pre-encryption build, or by a raw write to the
 * slot — which fails closed with a message that says what to do.</p>
 */
interface SecretCipher {

    String MARK = "enc:";

    String encrypt(String plain) throws Exception;

    String decrypt(String ciphertext) throws Exception;

    static boolean sealed(String value) {
        return value != null && value.startsWith(MARK);
    }

    /** The stored form of a secret; an already-sealed or empty value is returned as is. */
    default String seal(String value) throws Exception {
        if (value == null || value.isEmpty() || sealed(value)) {
            return value;
        }
        return MARK + encrypt(value);
    }

    /**
     * The secret behind a stored value. Empty stays empty; anything not sealed
     * by this engine is refused.
     */
    default String open(String key, String stored) {
        if (stored == null || stored.isEmpty()) {
            return stored;
        }
        if (!sealed(stored)) {
            throw new IllegalArgumentException(key + " is stored unencrypted; enter it again under "
                    + "Settings → OIDC Authentication so it is saved encrypted");
        }
        try {
            return decrypt(stored.substring(MARK.length()));
        } catch (Exception e) {
            throw new IllegalArgumentException(key + " could not be decrypted with this engine's key; "
                    + "enter it again under Settings → OIDC Authentication", e);
        }
    }

    /** A copy of the policy with every SECRET key sealed. */
    default Properties sealAll(Properties policy) throws Exception {
        Properties out = new Properties();
        out.putAll(policy);
        for (PolicySchema.Key key : PolicySchema.KEYS) {
            if (key.kind() == PolicySchema.Kind.SECRET && out.containsKey(key.name())) {
                out.setProperty(key.name(), seal(out.getProperty(key.name())));
            }
        }
        return out;
    }

    /** A copy of the policy with every SECRET key opened. */
    default Properties openAll(Properties stored) {
        Properties out = new Properties();
        out.putAll(stored);
        for (PolicySchema.Key key : PolicySchema.KEYS) {
            if (key.kind() == PolicySchema.Kind.SECRET && out.containsKey(key.name())) {
                out.setProperty(key.name(), open(key.name(), out.getProperty(key.name())));
            }
        }
        return out;
    }

    /** The engine's encryptor: the same key that protects its other stored secrets. */
    final class Engine implements SecretCipher {

        private final Encryptor encryptor;

        Engine(Encryptor encryptor) {
            this.encryptor = encryptor;
        }

        static Engine of(ConfigurationController configuration) {
            return new Engine(configuration.getEncryptor());
        }

        @Override
        public String encrypt(String plain) throws Exception {
            return encryptor.encrypt(plain);
        }

        @Override
        public String decrypt(String ciphertext) throws Exception {
            return encryptor.decrypt(ciphertext);
        }
    }
}
