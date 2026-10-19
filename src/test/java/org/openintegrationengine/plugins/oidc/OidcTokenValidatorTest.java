/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;

/**
 * The validator matrix from the plan, against a real local discovery + JWKS
 * endpoint and nimbus-generated keypairs.
 */
class OidcTokenValidatorTest {

    private static HttpServer server;
    private static String base;
    private static String issuer;
    private static RSAKey signingKey;
    private static RSAKey rogueKey;
    /** What /jwks currently publishes; swapped by the rotation test. */
    private static volatile JWKSet served;
    private static final AtomicInteger jwksFetches = new AtomicInteger();

    @BeforeAll
    static void startIdp() throws Exception {
        signingKey = new RSAKeyGenerator(2048).keyID("k1").generate();
        rogueKey = new RSAKeyGenerator(2048).keyID("k1").generate();   // same kid, different key
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        issuer = base;
        server.createContext("/.well-known/openid-configuration", exchange -> {
            byte[] body = ("{\"issuer\":\"" + issuer + "\",\"jwks_uri\":\"" + base + "/jwks\"}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        served = new JWKSet(signingKey.toPublicJWK());
        server.createContext("/jwks", exchange -> {
            jwksFetches.incrementAndGet();
            // Read from a mutable field so a test can ROTATE the published key
            // set mid-run, which is the only way to exercise the unknown-kid
            // refetch the validator relies on.
            byte[] body = served.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
    }

    @AfterAll
    static void stopIdp() {
        server.stop(0);
    }

    private static OidcTokenValidator validator() {
        Properties p = new Properties();
        p.setProperty("enabled", "true");
        p.setProperty("client-secret", "test-client-secret");   // required when enabled: the engine runs the flow
        p.setProperty("web-administrator-url", "https://admin.test");
        p.setProperty("roles.default", "Viewer");   // required whenever RBAC is on the classpath
        p.setProperty("discovery-url", base + "/.well-known/openid-configuration");
        p.setProperty("client-id", "client");
        return new OidcTokenValidator(OidcConfig.from(p), new DiscoveryClient());
    }

    private static JWTClaimsSet.Builder claims() {
        Date now = new Date();
        return new JWTClaimsSet.Builder()
                .issuer(issuer).audience("client").subject("subject-1")
                .issueTime(now).expirationTime(new Date(now.getTime() + 300_000));
    }

    private static String sign(JWTClaimsSet claims, RSAKey key) throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    @Test
    void acceptsAValidToken() throws Exception {
        JWTClaimsSet result = validator().validate(sign(claims().build(), signingKey));
        assertEquals("subject-1", result.getSubject());
    }

    @Test
    void cachesTheJwksAcrossValidations() throws Exception {
        OidcTokenValidator validator = validator();
        validator.validate(sign(claims().build(), signingKey));
        int fetchesAfterFirst = jwksFetches.get();
        validator.validate(sign(claims().build(), signingKey));
        assertEquals(fetchesAfterFirst, jwksFetches.get(), "second validation must reuse the cached JWKS");
    }

    @Test
    void rejectsAForeignSignature() {
        assertThrows(Exception.class, () -> validator().validate(sign(claims().build(), rogueKey)));
    }

    @Test
    void rejectsTheWrongIssuer() {
        assertThrows(Exception.class,
                () -> validator().validate(sign(claims().issuer("https://evil.example").build(), signingKey)));
    }

    @Test
    void rejectsTheWrongAudience() {
        assertThrows(Exception.class,
                () -> validator().validate(sign(claims().audience("someone-else").build(), signingKey)));
    }

    @Test
    void acceptsMultiAudienceOnlyWithMatchingAzp() throws Exception {
        JWTClaimsSet good = claims().audience(List.of("client", "other")).claim("azp", "client").build();
        assertEquals("subject-1", validator().validate(sign(good, signingKey)).getSubject());
        JWTClaimsSet bad = claims().audience(List.of("client", "other")).claim("azp", "other").build();
        assertThrows(Exception.class, () -> validator().validate(sign(bad, signingKey)));
    }

    @Test
    void rejectsAnExpiredToken() {
        Date past = new Date(System.currentTimeMillis() - 600_000);
        assertThrows(Exception.class, () -> validator()
                .validate(sign(claims().issueTime(new Date(past.getTime() - 1000)).expirationTime(past).build(), signingKey)));
    }

    @Test
    void rejectsAFutureNotBefore() {
        Date future = new Date(System.currentTimeMillis() + 600_000);
        assertThrows(Exception.class,
                () -> validator().validate(sign(claims().notBeforeTime(future).build(), signingKey)));
    }

    @Test
    void rejectsAStaleIssueTime() {
        // Fresh exp but an iat far past max-token-age: a replayed-but-unexpired
        // assertion must not be accepted.
        Date staleIat = new Date(System.currentTimeMillis() - 3_600_000);
        assertThrows(Exception.class,
                () -> validator().validate(sign(claims().issueTime(staleIat).build(), signingKey)));
    }

    @Test
    void rejectsSymmetricAlgorithms() throws Exception {
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims().build());
        jwt.sign(new MACSigner("0123456789012345678901234567890123456789".getBytes(StandardCharsets.UTF_8)));
        Exception e = assertThrows(Exception.class, () -> validator().validate(jwt.serialize()));
        assertTrue(e.getMessage().contains("algorithm"));
    }

    @Test
    void rejectsAnUnsignedToken() {
        String header = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8));
        String payload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(claims().build().toString().getBytes(StandardCharsets.UTF_8));
        assertThrows(Exception.class, () -> validator().validate(header + "." + payload + "."));
    }

    /**
     * Key rotation, the way it actually happens: the IdP publishes a new key
     * under a NEW kid and starts signing with it while the validator still holds
     * a cached key set that predates it. Nimbus's unknown-kid refetch is what
     * keeps logins working across that window — asserted in comments up to now,
     * but never exercised, because the suite served one static key for its whole
     * lifetime. A validator that could not refetch would reject every token
     * issued after any rotation until the engine restarted.
     */
    @Test
    void acceptsATokenSignedByAKeyPublishedAfterTheCacheWasPopulated() throws Exception {
        OidcTokenValidator validator = validator();
        // Populate the cache against the original key.
        validator.validate(sign(claims().build(), signingKey));
        int fetchesBeforeRotation = jwksFetches.get();

        RSAKey rotated = new RSAKeyGenerator(2048).keyID("k2-rotated").generate();
        served = new JWKSet(java.util.List.of(signingKey.toPublicJWK(), rotated.toPublicJWK()));

        JWTClaimsSet parsed = validator.validate(sign(claims().build(), rotated));
        assertEquals("subject-1", parsed.getSubject());
        assertTrue(jwksFetches.get() > fetchesBeforeRotation,
                "an unknown kid must trigger a refetch rather than failing against the cached set");
    }

    /**
     * The retired half of a rotation. Once the IdP stops publishing a key,
     * tokens it signed must stop validating — otherwise a leaked key stays
     * usable for as long as the cache does, which is the reason to rotate.
     */
    @Test
    void rejectsATokenSignedByAKeyTheIdpNoLongerPublishes() throws Exception {
        RSAKey retiring = new RSAKeyGenerator(2048).keyID("k3-retiring").generate();
        served = new JWKSet(java.util.List.of(signingKey.toPublicJWK(), retiring.toPublicJWK()));
        OidcTokenValidator validator = validator();
        validator.validate(sign(claims().build(), retiring));   // still published: fine

        served = new JWKSet(signingKey.toPublicJWK());           // retired
        OidcTokenValidator afterRetirement = validator();
        assertThrows(Exception.class, () -> afterRetirement.validate(sign(claims().build(), retiring)));

        served = new JWKSet(signingKey.toPublicJWK());           // leave the fixture as found
    }

    /* ---- the signature segment is malleable ------------------------------ */

    /**
     * One signed token, several spellings that all verify. The signature
     * segment is not covered by the signature: ECDSA accepts {@code n−s} as
     * readily as {@code s}, and a lenient base64url decoder ignores unused
     * trailing bits, padding and stray characters. A replay record keyed on the
     * whole string gave each spelling a fresh entry, so a spent token signed in
     * again after a one-character edit.
     *
     * <p>The property asserted is the one that matters: no spelling is accepted
     * a second time — it is either rejected by the validator or refused by the
     * cache. Only {@code n−s} is required to verify, because that is ECDSA
     * itself rather than a decoder's leniency; it keeps this test from passing
     * on a validator that happens to reject everything.</p>
     */
    @Test
    void noReSpellingOfASpentTokenIsAcceptedAgain() throws Exception {
        ECKey ecKey = new ECKeyGenerator(Curve.P_256).keyID("ec1").generate();
        served = new JWKSet(List.of(signingKey.toPublicJWK(), ecKey.toPublicJWK()));
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(ecKey.getKeyID()).build(), claims().build());
            jwt.sign(new ECDSASigner(ecKey));
            String original = jwt.serialize();

            OidcTokenValidator validator = validator();
            ReplayCache cache = new ReplayCache();
            long now = System.currentTimeMillis();
            validator.validate(original);
            assertTrue(cache.claim(original, 300_000, now), "the first use must be accepted");

            Map<String, String> respellings = respellings(original);
            assertDoesNotThrow(() -> validator.validate(respellings.get("s replaced by n - s")),
                    "ECDSA verifies n - s; if this stops verifying, the test below proves nothing");
            for (Map.Entry<String, String> respelled : respellings.entrySet()) {
                String token = respelled.getValue();
                assertNotEquals(original, token, respelled.getKey());
                assertFalse(signsIn(validator, cache, token, now),
                        respelled.getKey() + ": a spent token must not sign in again");
            }
        } finally {
            served = new JWKSet(signingKey.toPublicJWK());   // leave the fixture as found
        }
    }

    /**
     * The fix rests on this: the signed part — {@code header.payload} — has
     * exactly one spelling that verifies. Re-spell either segment the ways the
     * signature segment can be re-spelled and the signature no longer matches.
     * If a parser upgrade ever made one of these verify, keying on the signed
     * part would stop being enough; this is where that would show.
     */
    @Test
    void reSpellingTheSignedPartBreaksTheSignature() throws Exception {
        OidcTokenValidator validator = validator();
        String[] parts = sign(claims().build(), signingKey).split("\\.");
        Map<String, String> respellings = new LinkedHashMap<>();
        for (int segment = 0; segment < 2; segment++) {
            String name = segment == 0 ? "header" : "payload";
            for (Map.Entry<String, String> spelling : Map.of(
                    "unused bits", spareBits(parts[segment]),
                    "'=' padding", parts[segment] + "=",
                    "'==' padding", parts[segment] + "==",
                    "'*' appended", parts[segment] + "*").entrySet()) {
                String[] edited = parts.clone();
                edited[segment] = spelling.getValue();
                respellings.put(name + " " + spelling.getKey(), String.join(".", edited));
            }
        }
        ReplayCache cache = new ReplayCache();
        long now = System.currentTimeMillis();
        for (Map.Entry<String, String> respelled : respellings.entrySet()) {
            assertFalse(signsIn(validator, cache, respelled.getValue(), now),
                    respelled.getKey() + ": a re-spelled signed part must not verify");
        }
    }

    /** Validated, then claimed — exactly the plugin's order. A refusal anywhere is not a sign-in. */
    private static boolean signsIn(OidcTokenValidator validator, ReplayCache cache, String token, long now) {
        try {
            validator.validate(token);
            return cache.claim(token, 300_000, now);
        } catch (Exception refused) {
            return false;
        }
    }

    private static final String BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /** The segment with the lowest bit of its last character flipped: unused padding bits, when it has any. */
    private static String spareBits(String segment) {
        int last = BASE64URL.indexOf(segment.charAt(segment.length() - 1));
        return segment.substring(0, segment.length() - 1) + BASE64URL.charAt(last ^ 0x01);
    }

    /**
     * Spellings of an ES256 token's signature segment that decode to — or
     * verify as — the same signature. ES256 is R‖S, 32 bytes each: 64 bytes is
     * 86 base64url characters, the last of which carries 4 unused bits. Plus
     * surrounding whitespace, which the parser trims before it verifies.
     */
    private static Map<String, String> respellings(String token) {
        int dot = token.lastIndexOf('.');
        String signed = token.substring(0, dot + 1);
        String signature = token.substring(dot + 1);
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

        byte[] rs = Base64.getUrlDecoder().decode(signature);
        BigInteger n = Curve.P_256.toECParameterSpec().getOrder();
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(rs, 32, 64));
        byte[] negated = n.subtract(s).toByteArray();
        byte[] highS = Arrays.copyOf(rs, 64);
        Arrays.fill(highS, 32, 64, (byte) 0);
        int length = Math.min(32, negated.length);
        System.arraycopy(negated, negated.length - length, highS, 64 - length, length);

        Map<String, String> respellings = new LinkedHashMap<>();
        respellings.put("s replaced by n - s", signed + encoder.encodeToString(highS));
        respellings.put("unused trailing bits set", signed + spareBits(signature));
        respellings.put("'=' padding appended", signed + signature + "==");
        respellings.put("'*' appended", signed + signature + "*");
        // Not the signature segment, but the parser trims the whole token.
        respellings.put("leading space", " " + token);
        respellings.put("leading tab", "\t" + token);
        respellings.put("leading newline", "\n" + token);
        respellings.put("trailing newline", token + "\n");
        return respellings;
    }
}
