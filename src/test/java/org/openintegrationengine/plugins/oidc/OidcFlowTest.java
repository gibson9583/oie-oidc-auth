/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * The engine-run Authorization Code + PKCE flow against a local provider that
 * checks what a real one checks: the client secret, the PKCE verifier against
 * the challenge it was shown, and the redirect URI — and mints an ID token
 * carrying the nonce it was given.
 */
class OidcFlowTest {

    private static HttpServer server;
    private static String base;
    private static RSAKey key;
    private static volatile String issuedCode = "code-1";
    /** What the provider saw at /authorize is what /token must be answered with. */
    private static final AtomicReference<String> challenge = new AtomicReference<>();
    private static final AtomicReference<String> nonce = new AtomicReference<>();
    private static final AtomicReference<Map<String, String>> lastTokenRequest = new AtomicReference<>();
    /** Lets a test make the provider misbehave. */
    private static volatile String nonceOverride;
    private static volatile int tokenStatus = 200;

    @BeforeAll
    static void startProvider() throws Exception {
        key = new RSAKeyGenerator(2048).keyID("k1").generate();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/.well-known/openid-configuration", exchange -> respond(exchange, 200,
                "{\"issuer\":\"" + base + "\",\"jwks_uri\":\"" + base + "/jwks\",\"authorization_endpoint\":\"" + base
                        + "/authorize\",\"token_endpoint\":\"" + base + "/token\"}"));
        server.createContext("/jwks", exchange -> respond(exchange, 200, new JWKSet(key.toPublicJWK()).toString()));
        server.createContext("/token", exchange -> {
            Map<String, String> form = new HashMap<>();
            for (String pair : new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8).split("&")) {
                int eq = pair.indexOf('=');
                form.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
            lastTokenRequest.set(form);
            boolean ok = "authorization_code".equals(form.get("grant_type")) && issuedCode.equals(form.get("code"))
                    && "test-client-secret".equals(form.get("client_secret"))
                    && "https://admin.test/oidc/callback".equals(form.get("redirect_uri"))
                    && form.get("code_verifier") != null
                    && OidcTransaction.codeChallenge(form.get("code_verifier")).equals(challenge.get());
            if (!ok || tokenStatus != 200) {
                respond(exchange, ok ? tokenStatus : 400, "{\"error\":\"invalid_grant\"}");
                return;
            }
            try {
                JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(base).audience("client").subject("subject-1")
                        .claim("nonce", nonceOverride != null ? nonceOverride : nonce.get())
                        .claim("preferred_username", "jdoe").issueTime(new Date())
                        .expirationTime(new Date(System.currentTimeMillis() + 300_000)).build();
                SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("k1").build(), claims);
                jwt.sign(new RSASSASigner(key));
                respond(exchange, 200, "{\"access_token\":\"at\",\"token_type\":\"Bearer\",\"id_token\":\"" + jwt.serialize() + "\"}");
            } catch (Exception e) {
                respond(exchange, 500, "{\"error\":\"" + e + "\"}");
            }
        });
        server.start();
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    @AfterAll
    static void stopProvider() {
        server.stop(0);
    }

    @BeforeEach
    void reset() {
        nonceOverride = null;
        tokenStatus = 200;
        issuedCode = "code-1";
    }

    private static OidcConfig config() {
        Properties p = new Properties();
        p.setProperty("enabled", "true");
        p.setProperty("discovery-url", base + "/.well-known/openid-configuration");
        p.setProperty("client-id", "client");
        p.setProperty("client-secret", "test-client-secret");
        p.setProperty("web-administrator-url", "https://admin.test/");   // trailing slash is normalized away
        p.setProperty("roles.default", "Viewer");
        return OidcConfig.from(p);
    }

    /** Runs /start the way the servlet does and captures what the provider would see. */
    private static OidcFlow.Start start(OidcFlow flow, OidcConfig config, DiscoveryClient discovery, String returnPath) throws Exception {
        OidcFlow.Start started = flow.start(config, discovery.get(config), returnPath, false, System.currentTimeMillis());
        Map<String, String> query = query(started.authorizeUrl());
        challenge.set(query.get("code_challenge"));
        nonce.set(query.get("nonce"));
        return started;
    }

    private static Map<String, String> query(String url) {
        Map<String, String> out = new HashMap<>();
        for (String pair : URI.create(url).getRawQuery().split("&")) {
            int eq = pair.indexOf('=');
            out.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return out;
    }

    @Test
    void startBuildsTheAuthorizeUrlAndSealsTheAttempt() throws Exception {
        OidcConfig config = config();
        DiscoveryClient discovery = new DiscoveryClient();
        OidcFlow.Start started = start(new OidcFlow(), config, discovery, "/channels?x=1");

        assertTrue(started.authorizeUrl().startsWith(base + "/authorize?"));
        Map<String, String> q = query(started.authorizeUrl());
        assertEquals("client", q.get("client_id"));
        assertEquals("https://admin.test/oidc/callback", q.get("redirect_uri"), "built from the web administrator URL");
        assertEquals("code", q.get("response_type"));
        assertEquals("S256", q.get("code_challenge_method"));
        assertTrue(q.get("scope").startsWith("openid "), q.get("scope"));
        assertNotNull(q.get("state"));
        assertNotNull(q.get("nonce"));
        assertNotNull(q.get("code_challenge"));
        assertEquals(null, q.get("prompt"), "no forced re-authentication unless asked");

        OidcTransaction.Transaction txn = OidcTransaction.open(started.sealed(), "test-client-secret", System.currentTimeMillis());
        assertEquals(q.get("state"), txn.state());
        assertEquals(q.get("nonce"), txn.nonce());
        assertEquals(q.get("code_challenge"), OidcTransaction.codeChallenge(txn.verifier()), "the sealed verifier is the one behind the challenge");
        assertEquals("/channels?x=1", txn.returnPath());
        // The verifier is nowhere in what the browser sees.
        assertTrue(!started.authorizeUrl().contains(txn.verifier()));
    }

    @Test
    void completeExchangesTheCodeWithSecretAndVerifierAndChecksTheNonce() throws Exception {
        OidcConfig config = config();
        DiscoveryClient discovery = new DiscoveryClient();
        OidcFlow flow = new OidcFlow();
        OidcFlow.Start started = start(flow, config, discovery, "/dashboard");
        String state = query(started.authorizeUrl()).get("state");

        OidcFlow.Completion done = flow.complete(config, discovery.get(config), new OidcTokenValidator(config, discovery),
                started.sealed(), "code-1", state, System.currentTimeMillis());

        assertEquals("/dashboard", done.returnPath());
        assertEquals(nonce.get(), SignedJWT.parse(done.idToken()).getJWTClaimsSet().getStringClaim("nonce"));
        Map<String, String> sent = lastTokenRequest.get();
        assertEquals("test-client-secret", sent.get("client_secret"), "the secret is presented by the engine, never the browser");
        assertEquals("https://admin.test/oidc/callback", sent.get("redirect_uri"));
    }

    @Test
    void anEchoedStateThatDoesNotMatchIsRefusedBeforeAnyExchange() throws Exception {
        OidcConfig config = config();
        DiscoveryClient discovery = new DiscoveryClient();
        OidcFlow flow = new OidcFlow();
        OidcFlow.Start started = start(flow, config, discovery, "/");
        lastTokenRequest.set(null);

        assertThrows(SecurityException.class, () -> flow.complete(config, discovery.get(config),
                new OidcTokenValidator(config, discovery), started.sealed(), "code-1", "not-the-state", System.currentTimeMillis()));
        assertEquals(null, lastTokenRequest.get(), "no code exchange on a state mismatch");
        assertThrows(SecurityException.class, () -> flow.complete(config, discovery.get(config),
                new OidcTokenValidator(config, discovery), null, "code-1", "x", System.currentTimeMillis()));
    }

    @Test
    void aTokenMintedForAnotherAttemptIsRefusedByItsNonce() throws Exception {
        OidcConfig config = config();
        DiscoveryClient discovery = new DiscoveryClient();
        OidcFlow flow = new OidcFlow();
        OidcFlow.Start started = start(flow, config, discovery, "/");
        String state = query(started.authorizeUrl()).get("state");
        nonceOverride = "some-other-attempt";

        Exception e = assertThrows(Exception.class, () -> flow.complete(config, discovery.get(config),
                new OidcTokenValidator(config, discovery), started.sealed(), "code-1", state, System.currentTimeMillis()));
        assertTrue(String.valueOf(e.getMessage()).contains("nonce"), e.toString());
    }

    @Test
    void aFailedExchangeReportsTheProvidersReason() throws Exception {
        OidcConfig config = config();
        DiscoveryClient discovery = new DiscoveryClient();
        OidcFlow flow = new OidcFlow();
        OidcFlow.Start started = start(flow, config, discovery, "/");
        String state = query(started.authorizeUrl()).get("state");

        Exception e = assertThrows(Exception.class, () -> flow.complete(config, discovery.get(config),
                new OidcTokenValidator(config, discovery), started.sealed(), "a-code-the-provider-never-issued", state, System.currentTimeMillis()));
        assertTrue(e.getMessage().contains("invalid_grant"), e.getMessage());
    }

    @Test
    void theReturnPathNeverLeavesTheWebAdministrator() {
        assertEquals("/channels?x=1", OidcFlow.validReturnPath("/channels?x=1"));
        assertEquals("/channels", OidcFlow.validReturnPath("/foo/../channels"));
        for (String bad : new String[] { "https://evil.test", "//evil.test", "/\\evil.test", "javascript:alert(1)",
                "/..//evil.test", "/.//evil.test", "/foo/../..//evil.test", "/..//evil.test?x=1", "/a/../../..//evil.test",
                "/..\\/evil.test", "/x\r\nLocation: https://evil.test", null, "" }) {
            assertEquals("/", OidcFlow.validReturnPath(bad), String.valueOf(bad));
        }
    }
}
