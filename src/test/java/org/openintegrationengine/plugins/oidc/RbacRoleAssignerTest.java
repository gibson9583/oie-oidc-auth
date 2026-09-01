/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.diridium.rbac.RbacRepository;
import com.mirth.connect.model.User;

/**
 * Drives the reflection bridge against the recording fake in
 * {@code src/test/java/com/diridium/rbac} — the same FQCN the production code
 * resolves, so the method lookups themselves are under test.
 */
class RbacRoleAssignerTest {

    private RbacRepository rbac;

    @BeforeEach
    void setUp() {
        rbac = new RbacRepository();
        RbacRepository.current = rbac;
        RbacRepository.throwOnGetInstance = false;
        rbac.rolesByName.put("Administrator", 1);
        rbac.rolesByName.put("User", 2);
        rbac.rolesByName.put("Auditor", 3);
        rbac.adminRoleId = 1;
    }

    private static ClaimsMapper.Identity identity(String... roleClaims) {
        return new ClaimsMapper.Identity("jdoe", "https://idp#s1", new User(), List.of(roleClaims));
    }

    private static OidcConfig config(String map, String fallback, String sync) {
        return config(map, fallback, sync, false);
    }

    private static OidcConfig config(String map, String fallback, String sync, boolean infer) {
        Properties p = new Properties();
        p.setProperty("roles.map", map);
        p.setProperty("roles.default", fallback);
        p.setProperty("roles.sync", sync);
        p.setProperty("roles.infer", String.valueOf(infer));
        return OidcConfig.from(p);
    }

    @Test
    void assignsTheFirstMappedClaimInClaimOrder() {
        new RbacRoleAssigner().assign(7, false, identity("unmapped", "auditors", "admins"),
                config("admins=Administrator,auditors=Auditor", "User", "always"));
        assertEquals(1, rbac.assignments.size());
        assertEquals(3, rbac.assignments.get(0)[1]);   // auditors hit first in CLAIM order
    }

    @Test
    void fallsBackToTheDefaultRole() {
        new RbacRoleAssigner().assign(7, false, identity("nothing-mapped"), config("admins=Administrator", "User", "always"));
        assertEquals(2, rbac.userRoles.get(7));
    }

    @Test
    void anUnknownRoleNameIsANoOp() {
        new RbacRoleAssigner().assign(7, false, identity(), config("", "Nonexistent", "always"));
        assertTrue(rbac.assignments.isEmpty());
    }

    @Test
    void anUnchangedRoleIsNotReassigned() {
        rbac.userRoles.put(7, 2);
        new RbacRoleAssigner().assign(7, false, identity(), config("", "User", "always"));
        assertTrue(rbac.assignments.isEmpty());
    }

    @Test
    void neverDemotesTheLastAdministrator() {
        rbac.userRoles.put(7, 1);
        rbac.usersPerRole.put(1, 1);
        new RbacRoleAssigner().assign(7, false, identity(), config("", "User", "always"));
        assertTrue(rbac.assignments.isEmpty());
        assertEquals(1, rbac.userRoles.get(7));
    }

    @Test
    void demotesAnAdminWhenOthersRemain() {
        rbac.userRoles.put(7, 1);
        rbac.usersPerRole.put(1, 2);
        new RbacRoleAssigner().assign(7, false, identity(), config("", "User", "always"));
        assertEquals(2, rbac.userRoles.get(7));
    }

    @Test
    void syncNeverAndJitOnlySkipExistingUsers() {
        new RbacRoleAssigner().assign(7, false, identity(), config("", "User", "never"));
        new RbacRoleAssigner().assign(7, false, identity(), config("", "User", "jit-only"));
        assertTrue(rbac.assignments.isEmpty());

        new RbacRoleAssigner().assign(7, true, identity(), config("", "User", "jit-only"));
        assertEquals(1, rbac.assignments.size());
    }

    @Test
    void infersARoleFromAMatchingClaimNameWhenEnabled() {
        new RbacRoleAssigner().assign(7, false, identity("unmatched", "Auditor"), config("", "", "always", true));
        assertEquals(3, rbac.userRoles.get(7));
    }

    @Test
    void anExplicitMappingBeatsInference() {
        // "Administrator" would infer-match first in claim order, but the
        // explicit map is the operator's override and must win.
        new RbacRoleAssigner().assign(7, false, identity("Administrator", "auditors"),
                config("auditors=User", "", "always", true));
        assertEquals(2, rbac.userRoles.get(7));
    }

    @Test
    void inferenceOffIgnoresMatchingClaimNames() {
        new RbacRoleAssigner().assign(7, false, identity("Auditor"), config("", "", "always", false));
        assertTrue(rbac.assignments.isEmpty());
    }

    @Test
    void rbacFailureNeverBlocksTheLogin() {
        RbacRepository.throwOnGetInstance = true;
        // Must not throw — role sync is best-effort by design.
        new RbacRoleAssigner().assign(7, false, identity(), config("", "User", "always"));
        assertTrue(rbac.assignments.isEmpty());
    }
}
