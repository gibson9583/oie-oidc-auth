/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * The browser-facing half of the Authorization Code + PKCE flow, run by the
 * engine so that every deployment of the web administrator — the Node server
 * and the WAR alike — gets sign-on from the one place the policy lives.
 *
 * <p>Two steps, each reached by the web client as an authenticated-looking
 * XHR (the engine requires {@code X-Requested-With} on every API request, so
 * the provider's redirect can never land on an engine endpoint directly; the
 * client relays {@code code} and {@code state} instead):</p>
 * <ol>
 * <li>{@link #start} seals a fresh transaction and returns the provider URL
 * to send the browser to.</li>
 * <li>{@link #complete} opens the seal, checks the echoed state, exchanges the
 * code for tokens with the client secret and the PKCE verifier, and validates
 * the ID token including its nonce.</li>
 * </ol>
 */
final class OidcFlow {

    /** Where the provider sends the browser back: a route the web client owns. */
    static final String CALLBACK_PATH = "/oidc/callback";
    private static final int MAX_TOKEN_RESPONSE_BYTES = 1024 * 1024;

    record Start(String authorizeUrl, String sealed) {}
    record Completion(String idToken, String returnPath) {}

    private final HttpClient http;
    private final ObjectMapper json = new ObjectMapper();

    OidcFlow() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    OidcFlow(HttpClient http) {
        this.http = http;
    }

    /** The redirect URI to register at the provider, for this policy. */
    static String redirectUri(OidcConfig config) {
        return config.webAdministratorUrl() + CALLBACK_PATH;
    }

    Start start(OidcConfig config, DiscoveryClient.Metadata metadata, String returnPath, boolean forceLogin, long now) {
        if (metadata.authorizationEndpoint().isBlank()) {
            throw new IllegalStateException("the discovery document names no authorization_endpoint");
        }
        OidcTransaction.Transaction txn = OidcTransaction.fresh(validReturnPath(returnPath), now);
        Map<String, String> query = new LinkedHashMap<>();
        query.put("client_id", config.clientId());
        query.put("redirect_uri", redirectUri(config));
        query.put("response_type", "code");
        query.put("response_mode", "query");
        query.put("scope", String.join(" ", config.scopes()));
        query.put("state", txn.state());
        query.put("nonce", txn.nonce());
        query.put("code_challenge_method", "S256");
        query.put("code_challenge", OidcTransaction.codeChallenge(txn.verifier()));
        if (forceLogin) {
            // After a rejected attempt the provider's own session would otherwise
            // silently re-authenticate the same rejected account.
            query.put("prompt", "login");
        }
        String separator = metadata.authorizationEndpoint().contains("?") ? "&" : "?";
        String url = metadata.authorizationEndpoint() + separator + query.entrySet().stream()
                .map(e -> encode(e.getKey()) + "=" + encode(e.getValue())).collect(Collectors.joining("&"));
        return new Start(url, OidcTransaction.seal(txn, config.clientSecret()));
    }

    Completion complete(OidcConfig config, DiscoveryClient.Metadata metadata, OidcTokenValidator validator,
            String sealed, String code, String state, long now) throws Exception {
        if (sealed == null || sealed.isBlank()) {
            throw new SecurityException("no sign-in in progress in this browser");
        }
        OidcTransaction.Transaction txn = OidcTransaction.open(sealed, config.clientSecret(), now);
        if (state == null || !state.equals(txn.state())) {
            throw new SecurityException("state mismatch");
        }
        if (code == null || code.isBlank()) {
            throw new SecurityException("the provider returned no authorization code");
        }
        if (metadata.tokenEndpoint().isBlank()) {
            throw new IllegalStateException("the discovery document names no token_endpoint");
        }
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", redirectUri(config));
        form.put("client_id", config.clientId());
        form.put("client_secret", config.clientSecret());
        form.put("code_verifier", txn.verifier());
        String body = form.entrySet().stream().map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .collect(Collectors.joining("&"));
        HttpRequest request = HttpRequest.newBuilder(URI.create(metadata.tokenEndpoint()))
                .timeout(Duration.ofSeconds(15))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        HttpResponse<String> response = http.send(request, DiscoveryClient.bounded("the token response", MAX_TOKEN_RESPONSE_BYTES));
        JsonNode tokens = json.readTree(response.body());
        if (response.statusCode() != 200 || !tokens.path("id_token").isTextual()) {
            String reason = tokens.path("error").asText("HTTP " + response.statusCode());
            throw new IOException("token exchange failed: " + reason);
        }
        String idToken = tokens.get("id_token").asText();
        // The nonce ties the token to THIS attempt: a token minted for another
        // sign-in, replayed here with a valid code, fails on this line.
        validator.validate(idToken, txn.nonce());
        return new Completion(idToken, txn.returnPath());
    }

    /**
     * Where to send the browser after sign-in: a path on the web administrator,
     * never anywhere else. The value arrives from the browser via
     * {@code /start}, so an open redirect here would turn a genuine sign-in into
     * a phishing pivot off a trusted origin. Anything that is not "/" followed
     * by a non-separator collapses to "/", after normalization — dot segments
     * fold on parse, so "/..//evil" must be judged by what it becomes.
     */
    static String validReturnPath(String value) {
        String path = value == null ? "/" : value.trim();
        if (!path.startsWith("/") || path.startsWith("//") || path.startsWith("/\\") || path.contains("\r") || path.contains("\n")) {
            return "/";
        }
        // No route of the web administrator has an empty or "." segment, and
        // every escape shape that fools a parser starts with one.
        String rawPath = path.split("[?#]", 2)[0];
        if (rawPath.contains("//") || rawPath.contains("/./") || rawPath.endsWith("/.")) {
            return "/";
        }
        try {
            URI parsed = new URI("https", "local.invalid", null, null).resolve(path).normalize();
            // normalize() leaves a ".." that would climb above the root in place
            // rather than dropping it, so "/..//evil.test" comes back as
            // "/../evil.test" — same-origin, but not a path anyone typed. Refuse
            // anything that still tries to climb.
            if (!"local.invalid".equals(parsed.getHost()) || parsed.getRawPath() == null
                    || parsed.getRawPath().contains("/..")) {
                return "/";
            }
            String out = parsed.getRawPath() + (parsed.getRawQuery() != null ? "?" + parsed.getRawQuery() : "")
                    + (parsed.getRawFragment() != null ? "#" + parsed.getRawFragment() : "");
            return out.equals("/") || out.matches("^/[^/\\\\].*") ? out : "/";
        } catch (Exception e) {
            return "/";
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
