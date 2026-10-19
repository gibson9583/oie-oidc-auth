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
import java.util.regex.Pattern;

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

    /** hash of the token's signed content → the instant its record may be forgotten. */
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
        return seen.putIfAbsent(hash(signedContent(token)), now + ttlMillis) == null;
    }

    /**
     * What a token IS, for the purpose of remembering it: the
     * {@code header.payload} its signature covers.
     *
     * <p>Not the whole string. The signature segment is not covered by the
     * signature, and it can be re-spelled while still verifying — ECDSA accepts
     * {@code n−s} as readily as {@code s}, and the base64url decoder ignores
     * unused trailing bits, padding and stray characters. Keyed on the whole
     * string, every spelling was a fresh token and a spent one signed in again.</p>
     *
     * <p>The signed part must be canonical base64url — no whitespace, no
     * padding, nothing outside the alphabet — or the token is refused. The
     * parser is lenient there too: it trims, so {@code " " + token} verifies,
     * and keying on the raw prefix would hand that spelling a record of its
     * own. Refusing anything non-canonical, rather than mirroring what the
     * parser happens to forgive today, means a key is always exactly the bytes
     * the signature was checked over. No token from a real provider is
     * refused by this.</p>
     */
    static String signedContent(String token) {
        int last = token.lastIndexOf('.');
        String signed = last < 0 ? "" : token.substring(0, last);
        if (!CANONICAL_SIGNED_CONTENT.matcher(signed).matches()) {
            throw new SecurityException("not a compact JWS");
        }
        return signed;
    }

    private static final Pattern CANONICAL_SIGNED_CONTENT =
            Pattern.compile("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+");

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
