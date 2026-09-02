/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.net.URL;
import java.time.Instant;
import java.util.concurrent.TimeUnit;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.jwk.source.DefaultJWKSetCache;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
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
 * <p>The {@link RemoteJWKSet} is held for the lifetime of this validator (one
 * validator per config load), so JWKS fetches are cached across logins with
 * the configured TTL, and an unknown {@code kid} triggers nimbus's built-in
 * rate-limited refetch instead of a fetch per login.</p>
 */
public final class OidcTokenValidator {

    private final OidcConfig config;
    private final DiscoveryClient discovery;
    private String jwksUri;
    private RemoteJWKSet<SecurityContext> jwks;

    public OidcTokenValidator(OidcConfig config, DiscoveryClient discovery) {
        this.config = config;
        this.discovery = discovery;
    }

    /** The issuer this validator's discovery has seen, or null. Never fetches. */
    String cachedIssuer() {
        return discovery.cachedIssuer();
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
            long ttl = Math.max(config.jwksCacheTtlSeconds(), 2);
            jwks = new RemoteJWKSet<>(new URL(uri), null, new DefaultJWKSetCache(ttl, ttl / 2, TimeUnit.SECONDS));
            jwksUri = uri;
        }
        return jwks;
    }
}
