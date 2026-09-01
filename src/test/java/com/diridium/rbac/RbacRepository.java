/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package com.diridium.rbac;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Test-only stand-in for the RBAC extension's repository. The production
 * {@code RbacRoleAssigner} reaches RBAC via {@code Class.forName} on this
 * exact fully-qualified name, so placing a recording fake on the TEST
 * classpath exercises the real reflection path — signatures here mirror the
 * real repository (verified against the role-based-access-control repo).
 */
public class RbacRepository {

    public static RbacRepository current;
    public static boolean throwOnGetInstance;

    public static RbacRepository getInstance() {
        if (throwOnGetInstance) {
            throw new IllegalStateException("RBAC not ready");
        }
        return current;
    }

    public final Map<String, Integer> rolesByName = new HashMap<>();
    public final Map<Integer, Integer> userRoles = new HashMap<>();
    public final Map<Integer, Integer> usersPerRole = new HashMap<>();
    public Integer adminRoleId;
    public final List<int[]> assignments = new ArrayList<>();

    public Integer findRoleIdByName(String name) {
        return rolesByName.get(name);
    }

    public Integer getUserRoleId(int userId) {
        return userRoles.get(userId);
    }

    public Integer getAdminRoleId() {
        return adminRoleId;
    }

    public int countUsersByRoleId(int roleId) {
        return usersPerRole.getOrDefault(roleId, 0);
    }

    public void assignUserRole(int userId, int roleId) {
        assignments.add(new int[] { userId, roleId });
        userRoles.put(userId, roleId);
    }
}
