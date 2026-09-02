/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
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
}
