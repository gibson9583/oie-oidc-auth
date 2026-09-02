/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.net.URL;
import java.time.Instant;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.ResourceRetriever;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * Full JOSE validation of an ID token: signature against the provider's JWKS,
 * an asymmetric-only algorithm allowlist (kills alg=none and HS256 key
 * confusion), issuer, audience (+azp on multi-audience tokens), and an
 * exp/nbf/iat freshness window with configured skew.
 *
 * <p>The JWK source is held for the lifetime of this validator (one validator
 * per config load), so JWKS fetches are cached across logins with the
 * configured TTL, and an unknown {@code kid} triggers one rate-limited refetch
 * instead of a fetch per login.</p>
 */
public final class OidcTokenValidator {

    /** Same bounds as discovery: a key set is kilobytes, and a cloud provider is not 500 ms away. */
    private static final int JWKS_TIMEOUT_MILLIS = 10_000;
    private static final int JWKS_MAX_BYTES = 1024 * 1024;
    /** An unknown kid refetches at most this often; a rotation is not a per-second event. */
    private static final long JWKS_REFETCH_INTERVAL_MILLIS = 30_000;

    private final OidcConfig config;
    private final DiscoveryClient discovery;
    private String jwksUri;
    private JWKSource<SecurityContext> jwks;

    public OidcTokenValidator(OidcConfig config, DiscoveryClient discovery) {
        this.config = config;
        this.discovery = discovery;
    }

    /** The issuer this validator's discovery has seen, or null. Never fetches. */
    String cachedIssuer() {
        return discovery.cachedIssuer();
    }

    /** The discovery client this validator reads, for the sign-in flow's endpoints. */
    DiscoveryClient discovery() {
        return discovery;
    }

    /**
     * {@link #validate(String)} plus the nonce check that ties a token to the
     * sign-in attempt that asked for it. A token minted for some other attempt
     * — or obtained some other way — carries a different nonce or none.
     */
    public JWTClaimsSet validate(String token, String expectedNonce) throws Exception {
        JWTClaimsSet claims = validate(token);
        String nonce = claims.getStringClaim("nonce");
        if (expectedNonce == null || expectedNonce.isBlank() || !expectedNonce.equals(nonce)) {
            throw new BadJWTException("nonce rejected");
        }
        return claims;
    }

    public JWTClaimsSet validate(String token) throws Exception {
        DiscoveryClient.Metadata metadata = discovery.get(config);
        SignedJWT parsed = SignedJWT.parse(token);
        String alg = parsed.getHeader().getAlgorithm().getName();
        if (!config.allowedAlgorithms().contains(alg) || alg.startsWith("HS") || "none".equalsIgnoreCase(alg)) {
            throw new BadJOSEException("algorithm not allowed");
        }

        JWSKeySelector<SecurityContext> keySelector =
                new JWSVerificationKeySelector<>(JWSAlgorithm.parse(alg), jwksFor(metadata.jwksUri()));
        DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
        processor.setJWSKeySelector(keySelector);
        JWTClaimsSet claims = processor.process(token, null);

        if (!metadata.issuer().equals(claims.getIssuer()) || !claims.getAudience().contains(config.clientId())) {
            throw new BadJWTException("issuer or audience rejected");
        }
        if (claims.getAudience().size() > 1 && !config.clientId().equals(claims.getStringClaim("azp"))) {
            throw new BadJWTException("azp rejected");
        }

        Instant now = Instant.now();
        long skew = config.clockSkewSeconds();
        boolean expired = claims.getExpirationTime() == null
                || claims.getExpirationTime().toInstant().isBefore(now.minusSeconds(skew));
        boolean notYetValid = claims.getNotBeforeTime() != null
                && claims.getNotBeforeTime().toInstant().isAfter(now.plusSeconds(skew));
        boolean staleOrFuture = claims.getIssueTime() == null
                || claims.getIssueTime().toInstant().isBefore(now.minusSeconds(config.maxTokenAgeSeconds() + skew))
                || claims.getIssueTime().toInstant().isAfter(now.plusSeconds(skew));
        if (expired || notYetValid || staleOrFuture) {
            throw new BadJWTException("token lifetime rejected");
        }
        return claims;
    }

    /** One cached remote JWKS per URI; rebuilt only if discovery moves it. */
    private synchronized JWKSource<SecurityContext> jwksFor(String uri) throws Exception {
        if (jwks == null || !uri.equals(jwksUri)) {
            long ttlMillis = Math.max(config.jwksCacheTtlSeconds(), 2) * 1000L;
            // An explicit retriever. Left to nimbus, the fetch ran on its
            // defaults — 500 ms to connect, 500 ms to read, a 50 KB body — which
            // an on-premises engine reaching a cloud provider misses routinely,
            // and the miss lands on whichever sign-in follows each cache expiry.
            // Every other fetch in this plugin is bounded deliberately; this one
            // was bounded by accident, and too tightly.
            ResourceRetriever retriever = new DefaultResourceRetriever(JWKS_TIMEOUT_MILLIS, JWKS_TIMEOUT_MILLIS, JWKS_MAX_BYTES);
            jwks = JWKSourceBuilder.<SecurityContext>create(new URL(uri), retriever)
                    .cache(ttlMillis, Math.min(ttlMillis / 2, JWKS_TIMEOUT_MILLIS))
                    .rateLimited(JWKS_REFETCH_INTERVAL_MILLIS)
                    .build();
            jwksUri = uri;
        }
        return jwks;
    }
}
