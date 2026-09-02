/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

/**
 * Discovery fetching, caching, and the JWKS probe behind "Test connection".
 * The cache matters operationally: it decides how long the engine keeps using a
 * stale {@code jwks_uri} after the IdP moves one, and until now nothing
 * exercised its expiry at all.
 */
class DiscoveryClientTest {

    private static HttpServer server;
    private static String base;
    private static final AtomicInteger discoveryFetches = new AtomicInteger();
    private static volatile String jwksBody = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"k1\",\"n\":\"x\",\"e\":\"AQAB\"}]}";
    private static volatile String jwksPath = "/jwks";
    /** Overrides the whole discovery document when set. */
    private static volatile String discoveryBody;

    @BeforeAll
    static void startIdp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/.well-known/openid-configuration", exchange -> {
            discoveryFetches.incrementAndGet();
            respond(exchange, discoveryBody != null ? discoveryBody
                    : "{\"issuer\":\"" + base + "\",\"jwks_uri\":\"" + base + jwksPath + "\"}");
        });
        server.createContext("/jwks", exchange -> respond(exchange, jwksBody));
        server.createContext("/rotated-jwks", exchange -> respond(exchange, jwksBody));
        server.start();
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    @AfterAll
    static void stopIdp() {
        server.stop(0);
    }

    @BeforeEach
    void reset() {
        discoveryFetches.set(0);
        jwksPath = "/jwks";
        discoveryBody = null;
        jwksBody = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"k1\",\"n\":\"x\",\"e\":\"AQAB\"}]}";
    }

    private static OidcConfig config(long ttlSeconds) {
        Properties p = new Properties();
        p.setProperty("enabled", "true");
        p.setProperty("roles.default", "Viewer");   // required whenever RBAC is on the classpath
        p.setProperty("discovery-url", base + "/.well-known/openid-configuration");
        p.setProperty("client-id", "client");
        p.setProperty("jwks-cache-ttl-seconds", String.valueOf(ttlSeconds));
        return OidcConfig.from(p);
    }

    @Test
    void cachesTheDiscoveryDocumentWithinTheTtl() throws Exception {
        DiscoveryClient client = new DiscoveryClient();
        OidcConfig config = config(300);

        assertEquals(base, client.get(config).issuer());
        assertEquals(1, discoveryFetches.get());
        client.get(config);
        client.get(config);
        assertEquals(1, discoveryFetches.get(), "within the TTL the document must be served from cache");
    }

    /**
     * What the settings tab offers beside linked accounts: the issuer as the
     * engine has actually seen it, and nothing before then. Asking must never
     * fetch — the tab reads it on every GET of the configuration.
     */
    @Test
    void cachedIssuerIsKnownOnlyOnceDiscoveryHasBeenFetched() throws Exception {
        DiscoveryClient client = new DiscoveryClient();
        OidcConfig config = config(300);

        assertNull(client.cachedIssuer(), "nothing has been fetched yet");
        assertEquals(0, discoveryFetches.get(), "asking must not fetch");

        client.get(config);
        assertEquals(base, client.cachedIssuer());
        assertEquals(1, discoveryFetches.get(), "and asking afterwards must not fetch either");
        client.cachedIssuer();
        assertEquals(1, discoveryFetches.get());
    }

    /**
     * The expiry side, which decides how long a moved {@code jwks_uri} keeps
     * being used. A zero TTL makes every call re-fetch, so the endpoint change
     * is observed rather than pinned to whatever was cached at startup.
     */
    @Test
    void refetchesOnceTheTtlHasLapsed() throws Exception {
        DiscoveryClient client = new DiscoveryClient();
        OidcConfig config = config(0);

        assertEquals(base + "/jwks", client.get(config).jwksUri());
        assertEquals(1, discoveryFetches.get());

        jwksPath = "/rotated-jwks";
        assertEquals(base + "/rotated-jwks", client.get(config).jwksUri(),
                "an expired cache must pick up an IdP-side endpoint change");
        assertTrue(discoveryFetches.get() > 1);
    }

    @Test
    void rejectsADiscoveryDocumentMissingItsEndpoints() {
        // A structurally valid document that simply omits jwks_uri — a
        // misconfigured provider. It must fail loudly rather than hand back a
        // Metadata with blank fields that only breaks at the first login.
        discoveryBody = "{\"issuer\":\"" + base + "\"}";
        DiscoveryClient client = new DiscoveryClient();
        assertThrows(Exception.class, () -> client.get(config(0)));
    }

    /**
     * "Test connection" reports what it verified, so it must not count keys that
     * cannot verify anything. A JWKS of encryption-only or symmetric keys is
     * reachable and parses, yet every real login still fails — reporting those
     * as signing keys is exactly the false confidence the probe exists to remove.
     */
    @Test
    void countsOnlyKeysThatCouldVerifyAToken() throws Exception {
        DiscoveryClient client = new DiscoveryClient();
        OidcConfig config = config(0);
        DiscoveryClient.Metadata metadata = client.get(config);

        jwksBody = "{\"keys\":["
                + "{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"a\",\"alg\":\"RS256\"},"
                + "{\"kty\":\"RSA\",\"use\":\"enc\",\"kid\":\"b\"},"
                + "{\"kty\":\"oct\",\"kid\":\"c\",\"alg\":\"HS256\"}]}";
        assertEquals(1, client.probeKeys(config, metadata), "only the sig-capable RSA key counts");

        // An algorithm the policy does not allow is not usable either.
        jwksBody = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"a\",\"alg\":\"PS512\"}]}";
        Properties narrow = new Properties();
        narrow.setProperty("enabled", "true");
        narrow.setProperty("roles.default", "Viewer");
        narrow.setProperty("discovery-url", base + "/.well-known/openid-configuration");
        narrow.setProperty("client-id", "client");
        narrow.setProperty("allowed-algorithms", "RS256");
        assertThrows(IOException.class, () -> client.probeKeys(OidcConfig.from(narrow), metadata));
    }

    @Test
    void rejectsAnEmptyKeySet() throws Exception {
        DiscoveryClient client = new DiscoveryClient();
        OidcConfig config = config(0);
        DiscoveryClient.Metadata metadata = client.get(config);

        jwksBody = "{\"keys\":[]}";
        assertThrows(IOException.class, () -> client.probeKeys(config, metadata));
    }
}
