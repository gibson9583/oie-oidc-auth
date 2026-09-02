/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.mirth.connect.model.User;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Maps validated ID-token claims to the engine identity: the login username
 * (normalized NFKC + lowercase so IdP-side case drift cannot fork accounts),
 * the {@code issuer#subject} binding string, a JIT-provisionable profile, and
 * the raw role claim values for the RBAC bridge.
 */
public final class ClaimsMapper {

    public record Identity(String username, String subject, User profile, List<String> roles) {}

    public Identity map(JWTClaimsSet claims, OidcConfig config) throws Exception {
        String raw = claims.getStringClaim(config.usernameClaim());
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("username claim missing");
        }
        String username = config.usernamePrefix()
                + Normalizer.normalize(raw.trim(), Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
        if (!username.matches("[a-z0-9._@+:-]{1,128}")) {
            throw new IllegalArgumentException("username claim contains unsupported characters");
        }
        if (claims.getSubject() == null || claims.getSubject().isBlank()) {
            throw new IllegalArgumentException("subject claim missing");
        }

        User profile = new User();
        profile.setUsername(username);
        profile.setEmail(text(claims, config.emailClaim()));
        profile.setOrganization(text(claims, config.organizationClaim()));
        String name = text(claims, config.nameClaim());
        if (name != null) {
            int split = name.lastIndexOf(' ');
            profile.setFirstName(split > 0 ? name.substring(0, split) : name);
            profile.setLastName(split > 0 ? name.substring(split + 1) : "");
        }

        Object roleClaim = claimAt(claims, config.rolesClaim());
        List<String> roles = new ArrayList<>();
        if (roleClaim instanceof Collection<?> all) {
            // Already a list — each element is one role, verbatim. A value that
            // happens to contain a comma is that role's actual name.
            for (Object value : all) {
                roles.add(String.valueOf(value));
            }
        } else if (roleClaim != null) {
            // A SCALAR claim is delimited in practice: providers emit
            // "admins,auditors", and scope-style claims are space-separated.
            // Added verbatim it becomes one token that matches no roles.map
            // entry and no role name, so the whole mapping silently does
            // nothing — the failure looks identical to "the claim is missing".
            //
            // Comma wins when present, and whitespace is only a separator in its
            // absence. Splitting on both unconditionally would break every role
            // whose NAME contains a space — "Site Administrators", "Read Only" —
            // turning one silent mapping failure into another for configurations
            // that worked before.
            String scalar = String.valueOf(roleClaim).trim();
            for (String part : scalar.split(scalar.indexOf(',') >= 0 ? "\\s*,\\s*" : "\\s+")) {
                if (!part.isBlank()) {
                    roles.add(part.trim());
                }
            }
        }

        return new Identity(username, claims.getIssuer() + "#" + claims.getSubject(), profile, roles);
    }

    private String text(JWTClaimsSet claims, String key) {
        Object value = claims.getClaim(key);
        return value == null ? null : String.valueOf(value);
    }

    /**
     * Resolves a claim by name, or by DOTTED PATH into nested claim objects.
     * Keycloak — the IdP this is most often pointed at — keeps neither of its
     * role constructs at the top level: realm roles live at
     * {@code realm_access.roles} and client roles at
     * {@code resource_access.<client-id>.roles} (its own mapper names the claim
     * {@code resource_access.${client_id}.roles} and expands the dots into
     * nested JSON). Without this, only flat claims like {@code groups} are
     * reachable, which forces operators to model roles as group membership.
     *
     * <p>An EXACT top-level match is tried first, so an IdP that literally
     * names a claim with dots still resolves and no existing config changes
     * meaning.</p>
     */
    private static Object claimAt(JWTClaimsSet claims, String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        Object exact = claims.getClaim(path);
        if (exact != null || path.indexOf('.') < 0) {
            return exact;
        }
        String[] segments = path.split("\\.");
        Object node = claims.getClaim(segments[0]);
        for (int i = 1; i < segments.length && node != null; i++) {
            node = node instanceof Map<?, ?> level ? level.get(segments[i]) : null;
        }
        return node;
    }
}
