/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The state of one sign-in attempt between {@code /start} and
 * {@code /callback}, sealed so it can ride in the browser as a cookie.
 *
 * <p>The provider hands the browser back a {@code code}; whoever holds the
 * matching PKCE verifier and the client secret can turn it into a token. The
 * verifier therefore never leaves the engine in the clear: it travels sealed
 * under a key derived from the client secret, together with the {@code state}
 * the provider must echo and the {@code nonce} the token must carry. Opening
 * the seal is the callback's proof that it is completing the attempt this
 * engine started, in this browser, within ten minutes.</p>
 */
final class OidcTransaction {

    static final long TTL_MILLIS = 10 * 60 * 1000;
    /** Tolerated forward clock drift between sealing and opening. */
    private static final long FUTURE_TOLERANCE_MILLIS = 30 * 1000;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    record Transaction(String state, String nonce, String verifier, String returnPath, long created) {}

    private OidcTransaction() {}

    /** A fresh attempt: independent, full-entropy state, nonce, and verifier. */
    static Transaction fresh(String returnPath, long now) {
        // 48 random bytes encode to 64 characters, inside PKCE's 43–128 range.
        return new Transaction(random(32), random(32), random(48), returnPath, now);
    }

    /** The S256 challenge for a transaction's verifier. */
    static String codeChallenge(String verifier) {
        return B64.encodeToString(sha256(verifier.getBytes(StandardCharsets.US_ASCII)));
    }

    static String seal(Transaction txn, String secret) {
        try {
            byte[] iv = new byte[12];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keyFor(secret), new GCMParameterSpec(128, iv));
            // returnPath last: it is the one field that may contain anything,
            // so it must not need escaping to be split back out.
            String payload = txn.state() + "\n" + txn.nonce() + "\n" + txn.verifier() + "\n" + txn.created()
                    + "\n" + txn.returnPath();
            byte[] sealed = cipher.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return B64.encodeToString(iv) + "." + B64.encodeToString(sealed);
        } catch (Exception e) {
            throw new IllegalStateException("could not seal the sign-in transaction", e);
        }
    }

    /**
     * @throws IllegalArgumentException with message {@code expired transaction}
     *         when the seal is genuine but too old, and {@code invalid
     *         transaction} for anything else — including a seal made under a
     *         different client secret.
     */
    static Transaction open(String sealed, String secret, long now) {
        String[] parts = sealed == null ? new String[0] : sealed.split("\\.", -1);
        if (parts.length != 2) {
            throw new IllegalArgumentException("invalid transaction");
        }
        String payload;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keyFor(secret), new GCMParameterSpec(128, B64D.decode(parts[0])));
            payload = new String(cipher.doFinal(B64D.decode(parts[1])), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid transaction");
        }
        String[] fields = payload.split("\n", 5);
        if (fields.length != 5) {
            throw new IllegalArgumentException("invalid transaction");
        }
        long created;
        try {
            created = Long.parseLong(fields[3]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid transaction");
        }
        if (created > now + FUTURE_TOLERANCE_MILLIS || now - created > TTL_MILLIS) {
            throw new IllegalArgumentException("expired transaction");
        }
        return new Transaction(fields[0], fields[1], fields[2], fields[4], created);
    }

    /**
     * Domain-separated from the secret, so a seal cannot be opened by anything
     * that merely knows the secret's use elsewhere, and a secret change
     * invalidates every in-flight attempt — which is the right outcome.
     */
    private static SecretKeySpec keyFor(String secret) {
        return new SecretKeySpec(sha256(("oie-oidc-transaction-v1\n" + secret).getBytes(StandardCharsets.UTF_8)), "AES");
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String random(int bytes) {
        byte[] buffer = new byte[bytes];
        RANDOM.nextBytes(buffer);
        return B64.encodeToString(buffer);
    }
}
