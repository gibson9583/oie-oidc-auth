/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Fetches and caches the provider's discovery document. The cache TTL reuses
 * {@code jwks-cache-ttl-seconds}: both answer "how quickly must an IdP-side
 * change (key rotation, endpoint move) be noticed", and one knob is enough.
 */
public final class DiscoveryClient {

    public record Metadata(String issuer, String jwksUri) {}

    private final HttpClient http;
    private final ObjectMapper json = new ObjectMapper();
    private Metadata cached;
    private long expires;

    public DiscoveryClient() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    DiscoveryClient(HttpClient http) {
        this.http = http;
    }

    /**
     * Fetches the JWKS the discovery document points at and returns how many
     * keys it holds. Discovery alone proves only that the document parses —
     * "Test connection" reporting success while the key set is unreachable
     * (firewall, wrong host, empty JWKS) means the first real login is what
     * discovers the problem, which is the opposite of what a test is for.
     */
    public int probeKeys(OidcConfig config, Metadata metadata) throws Exception {
        // jwks_uri comes from the REMOTE discovery document, not from operator
        // input, so re-check the scheme here rather than trusting that get()
        // already did — this method is one call away from being reused.
        OidcConfig.requireHttps(metadata.jwksUri(), "jwks_uri");
        HttpRequest request = HttpRequest.newBuilder(URI.create(metadata.jwksUri()))
                .timeout(Duration.ofSeconds(10))
                .header("Accept", "application/json")
                .build();
        // Bounded: the request timeout covers response HEADERS, not the body, so
        // an endpoint that trickles bytes could hold this thread indefinitely and
        // grow the heap — and the URL it points at is chosen remotely.
        HttpResponse<String> response = http.send(request, bounded("the JWKS at " + metadata.jwksUri()));
        if (response.statusCode() != 200) {
            throw new IOException("JWKS fetch failed with HTTP " + response.statusCode() + " at " + metadata.jwksUri());
        }
        JsonNode keys = json.readTree(response.body()).path("keys");
        if (!keys.isArray() || keys.isEmpty()) {
            throw new IOException("JWKS at " + metadata.jwksUri() + " contains no keys");
        }
        // Count only keys that could actually verify a token under this policy.
        // A JWKS of encryption-only or symmetric keys is reachable and parses,
        // yet every real login still fails — reporting "3 keys" there is exactly
        // the false confidence this probe exists to remove.
        int usable = 0;
        for (JsonNode key : keys) {
            String use = key.path("use").asText("");
            String alg = key.path("alg").asText("");
            boolean signing = use.isEmpty() || "sig".equals(use);
            boolean allowed = alg.isEmpty() || config.allowedAlgorithms().contains(alg);
            if (signing && allowed && !"oct".equals(key.path("kty").asText(""))) {
                usable++;
            }
        }
        if (usable == 0) {
            throw new IOException("JWKS at " + metadata.jwksUri()
                    + " has no signing keys matching allowed-algorithms " + config.allowedAlgorithms());
        }
        return usable;
    }

    /** Identity documents are kilobytes; anything larger is not one of them. */
    private static final int MAX_BODY_BYTES = 1024 * 1024;

    /**
     * Stops reading at {@link #MAX_BODY_BYTES} instead of checking afterwards.
     *
     * <p>The obvious spelling — mapping over {@code ofByteArray()} and testing
     * the length — does not bound anything: the subscriber accumulates the
     * ENTIRE body first, so the check reports a limit it has already exceeded.
     * Measured against the previous version: a 32 MiB body was fully buffered
     * before the exception fired, and 256 MiB against a small heap thrashed for
     * minutes without ever reaching the check. Both of these URLs are chosen
     * remotely — {@code jwks_uri} comes out of the discovery document — so the
     * bound has to be enforced while reading, by cancelling the subscription.</p>
     */
    private static HttpResponse.BodyHandler<String> bounded(String what) {
        return info -> new HttpResponse.BodySubscriber<String>() {
            private final java.util.concurrent.CompletableFuture<String> result = new java.util.concurrent.CompletableFuture<>();
            private final java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
            private java.util.concurrent.Flow.Subscription subscription;

            @Override
            public java.util.concurrent.CompletionStage<String> getBody() {
                return result;
            }

            @Override
            public void onSubscribe(java.util.concurrent.Flow.Subscription s) {
                this.subscription = s;
                s.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(java.util.List<java.nio.ByteBuffer> items) {
                for (java.nio.ByteBuffer item : items) {
                    if (buffer.size() + item.remaining() > MAX_BODY_BYTES) {
                        subscription.cancel();
                        result.completeExceptionally(
                                new IOException(what + " exceeded " + MAX_BODY_BYTES + " bytes; refusing to read further"));
                        return;
                    }
                    byte[] chunk = new byte[item.remaining()];
                    item.get(chunk);
                    buffer.writeBytes(chunk);
                }
            }

            @Override
            public void onError(Throwable e) {
                result.completeExceptionally(e);
            }

            @Override
            public void onComplete() {
                result.complete(buffer.toString(java.nio.charset.StandardCharsets.UTF_8));
            }
        };
    }

    public synchronized Metadata get(OidcConfig config) throws Exception {
        if (cached != null && expires > System.currentTimeMillis()) {
            return cached;
        }
        // A blank URL must say so — falling through to the HTTPS check turns
        // "you haven't entered one" into a baffling protocol complaint.
        if (config.discoveryUrl() == null || config.discoveryUrl().isBlank()) {
            throw new IOException("discovery-url is required");
        }
        OidcConfig.requireHttps(config.discoveryUrl(), "discovery-url");
        HttpRequest request = HttpRequest.newBuilder(URI.create(config.discoveryUrl()))
                .timeout(Duration.ofSeconds(10))
                .header("Accept", "application/json")
                .build();
        // Bounded too. This is the fetch on the LOGIN path, and it was the
        // unguarded one — the bound was added to the "Test connection" probe
        // beside it and not to this.
        HttpResponse<String> response = http.send(request, bounded("the discovery document at " + config.discoveryUrl()));
        if (response.statusCode() != 200) {
            throw new IOException("OIDC discovery failed");
        }
        JsonNode node = json.readTree(response.body());
        String issuer = node.path("issuer").asText();
        String jwksUri = node.path("jwks_uri").asText();
        if (issuer.isBlank() || jwksUri.isBlank()) {
            throw new IOException("Incomplete OIDC discovery document");
        }
        // The document is attacker-influencable only if discovery itself is —
        // but a compromised or misconfigured IdP must still not downgrade key
        // fetching to plaintext.
        OidcConfig.requireHttps(jwksUri, "jwks_uri");
        cached = new Metadata(issuer, jwksUri);
        expires = System.currentTimeMillis() + config.jwksCacheTtlSeconds() * 1000;
        return cached;
    }
}
