/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;

import com.nimbusds.jwt.JWTClaimsSet;

class ClaimsMapperTest {

    private static OidcConfig config(String prefix) {
        Properties p = new Properties();
        p.setProperty("username-prefix", prefix);
        return OidcConfig.from(p);
    }

    private static OidcConfig rolesFrom(String claimPath) {
        Properties p = new Properties();
        p.setProperty("roles.claim", claimPath);
        return OidcConfig.from(p);
    }

    private static JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder().issuer("https://idp.example").subject("subject-1");
    }

    @Test
    void normalizesTheUsernameAndBuildsTheBinding() throws Exception {
        ClaimsMapper.Identity identity = new ClaimsMapper().map(
                claims().claim("preferred_username", "  JDoe ")
                        .claim("email", "jdoe@example.test")
                        .claim("name", "Jane van Doe").build(),
                config(""));
        assertEquals("jdoe", identity.username());
        assertEquals("https://idp.example#subject-1", identity.subject());
        assertEquals("jdoe@example.test", identity.profile().getEmail());
        assertEquals("Jane van", identity.profile().getFirstName());
        assertEquals("Doe", identity.profile().getLastName());
    }

    @Test
    void appliesTheNamespacePrefix() throws Exception {
        ClaimsMapper.Identity identity = new ClaimsMapper().map(
                claims().claim("preferred_username", "jdoe").build(), config("sso:"));
        assertEquals("sso:jdoe", identity.username());
    }

    @Test
    void readsRolesFromAListOrAScalar() throws Exception {
        ClaimsMapper.Identity list = new ClaimsMapper().map(
                claims().claim("preferred_username", "jdoe").claim("groups", List.of("a", "b")).build(), config(""));
        assertEquals(List.of("a", "b"), list.roles());

        ClaimsMapper.Identity scalar = new ClaimsMapper().map(
                claims().claim("preferred_username", "jdoe").claim("groups", "only").build(), config(""));
        assertEquals(List.of("only"), scalar.roles());
    }

    /** Keycloak's realm roles: nested under realm_access, never top level. */
    @Test
    void readsRolesFromANestedPath() throws Exception {
        ClaimsMapper.Identity identity = new ClaimsMapper().map(
                claims().claim("preferred_username", "jdoe")
                        .claim("realm_access", Map.of("roles", List.of("Editor", "offline_access"))).build(),
                rolesFrom("realm_access.roles"));

        assertEquals(List.of("Editor", "offline_access"), identity.roles());
    }

    /** Keycloak's client roles: two levels deep, keyed by client id. */
    @Test
    void readsRolesFromADeeplyNestedPerClientPath() throws Exception {
        ClaimsMapper.Identity identity = new ClaimsMapper().map(
                claims().claim("preferred_username", "jdoe")
                        .claim("resource_access", Map.of(
                                "oie-web-administrator", Map.of("roles", List.of("Editor")),
                                "account", Map.of("roles", List.of("view-profile")))).build(),
                rolesFrom("resource_access.oie-web-administrator.roles"));

        assertEquals(List.of("Editor"), identity.roles());
    }

    /**
     * A claim whose LITERAL name contains dots still wins, so turning on path
     * support cannot change what an existing configuration resolves to.
     */
    @Test
    void anExactClaimNameBeatsThePathWalk() throws Exception {
        ClaimsMapper.Identity identity = new ClaimsMapper().map(
                claims().claim("preferred_username", "jdoe")
                        .claim("realm_access.roles", List.of("literal"))
                        .claim("realm_access", Map.of("roles", List.of("nested"))).build(),
                rolesFrom("realm_access.roles"));

        assertEquals(List.of("literal"), identity.roles());
    }

    @Test
    void aPathThatDeadEndsYieldsNoRolesRatherThanThrowing() throws Exception {
        ClaimsMapper.Identity identity = new ClaimsMapper().map(
                claims().claim("preferred_username", "jdoe")
                        .claim("realm_access", "not-an-object").build(),
                rolesFrom("realm_access.roles.deeper"));

        assertEquals(List.of(), identity.roles());
    }

    @Test
    void rejectsAMissingUsernameClaim() {
        assertThrows(IllegalArgumentException.class, () -> new ClaimsMapper().map(claims().build(), config("")));
    }

    @Test
    void rejectsAMissingSubject() {
        JWTClaimsSet noSubject = new JWTClaimsSet.Builder().issuer("https://idp.example")
                .claim("preferred_username", "jdoe").build();
        assertThrows(IllegalArgumentException.class, () -> new ClaimsMapper().map(noSubject, config("")));
    }

    @Test
    void rejectsUnsupportedCharacters() {
        assertThrows(IllegalArgumentException.class, () -> new ClaimsMapper().map(
                claims().claim("preferred_username", "jane doe!").build(), config("")));
    }
}
