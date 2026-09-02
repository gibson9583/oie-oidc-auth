/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.mirth.connect.server.controllers.ControllerFactory;

/**
 * Soft bridge to the role-based-access-control extension, reached by
 * reflection so this plugin has no compile-time or install-time dependency on
 * it. Policy: first {@code roles.map} hit in claim order, else
 * {@code roles.default}, else leave the role unchanged; never demote the last
 * administrator (mirroring RBAC's own AdminRoleGuard); RBAC absent, not ready,
 * or failing NEVER blocks a login — role sync is best-effort by design.
 */
public final class RbacRoleAssigner {

    private static final Logger log = LogManager.getLogger(RbacRoleAssigner.class);

    static final String RBAC_REPOSITORY = "com.diridium.rbac.RbacRepository";

    /**
     * Whether the RBAC extension is on the classpath. Presence only — it says
     * nothing about whether RBAC has finished starting, which is why role sync
     * itself stays best-effort. Used by {@link OidcConfig} to decide whether
     * {@code roles.default} is mandatory: without RBAC there are no roles to
     * assign, so requiring one would reject a perfectly valid configuration.
     */
    public static boolean isInstalled() {
        try {
            // initialize=false: presence is the question, and running RBAC's
            // static initializers to answer it would let an ExceptionInInitializer
            // Error escape a plain ClassNotFoundException catch — out through
            // OidcConfig.from and the plugin's apply(), which catches Exception,
            // and into engine startup. Throwable for the same reason.
            Class.forName(RBAC_REPOSITORY, false, RbacRoleAssigner.class.getClassLoader());
            return true;
        } catch (Throwable e) {
            return false;
        }
    }

    public void assign(int userId, boolean created, ClaimsMapper.Identity identity, OidcConfig config) {
        if ("never".equals(config.rolesSync()) || ("jit-only".equals(config.rolesSync()) && !created)) {
            return;
        }
        String role = null;
        for (String claim : identity.roles()) {
            if (config.rolesMap().containsKey(claim)) {
                role = config.rolesMap().get(claim);
                break;
            }
        }
        boolean nothingConfigured = (role == null || role.isBlank()) && !config.rolesInfer()
                && (config.defaultRole() == null || config.defaultRole().isBlank());
        if (nothingConfigured) {
            // Says WHY nothing happened. Silence here reads identically to a
            // working sync that had nothing to change, which is a slow thing to
            // diagnose from the outside.
            log.debug("OIDC role sync skipped: no roles.map hit, roles.infer off, no roles.default (claims: {})",
                    identity.roles());
            return;
        }
        try {
            Class<?> type = Class.forName(RBAC_REPOSITORY);
            Object repo = type.getMethod("getInstance").invoke(null);
            // Opt-in inference: with no explicit mapping matched, a claim value
            // that IS an existing role name (exact match, claim order) wins.
            // Explicit mappings always take precedence so operators can rename
            // or override; inference is off by default because any matching
            // value — including "Administrator" — grants that role.
            if ((role == null || role.isBlank()) && config.rolesInfer()) {
                for (String claim : identity.roles()) {
                    if (call(type, repo, "findRoleIdByName", new Class[] { String.class }, claim) != null) {
                        role = claim;
                        break;
                    }
                }
            }
            if (role == null || role.isBlank()) {
                role = config.defaultRole();
                // Routine, so DEBUG: the operator asked for no per-login role
                // chatter at the default level. The claim name and what it held
                // are still here for anyone diagnosing "why does everyone get the
                // default" — the README's roles-claim recipe is the usual answer
                // (a mapper writing to the access token only).
                log.debug("OIDC assigning the default role '{}' to user id {}: claim '{}' carried {}",
                        role, userId, config.rolesClaim(), identity.roles());
            }
            if (role == null || role.isBlank()) {
                return;
            }
            Integer target = (Integer) call(type, repo, "findRoleIdByName", new Class[] { String.class }, role);
            if (target == null) {
                log.warn("OIDC role '{}' does not exist; leaving role unchanged", role);
                return;
            }
            Integer current = (Integer) call(type, repo, "getUserRoleId", new Class[] { int.class }, userId);
            if (target.equals(current)) {
                return;
            }
            Integer admin = (Integer) call(type, repo, "getAdminRoleId", new Class[] {});
            if (admin != null && admin.equals(current)
                    && (Integer) call(type, repo, "countUsersByRoleId", new Class[] { int.class }, admin) <= 1) {
                log.warn("OIDC refused to demote the last RBAC administrator");
                return;
            }
            call(type, repo, "assignUserRole", new Class[] { int.class, int.class }, userId, target);
            // Only fires on an actual CHANGE (an unchanged role returned above).
            // DEBUG at the operator's request; RBAC's own assignment is the record.
            log.debug("OIDC assigned RBAC role '{}' to user id {}", role, userId);
            // RBAC caches per-user authorization; a stale entry would keep the
            // OLD role's permissions live for this session.
            Object auth = ControllerFactory.getFactory().createAuthorizationController();
            try {
                auth.getClass().getMethod("invalidateCache", Integer.class).invoke(auth, userId);
            } catch (ReflectiveOperationException ignored) {
                // Not the RBAC controller (plugin half-installed) — nothing to invalidate.
            }
        } catch (Throwable e) {
            log.warn("OIDC RBAC role synchronization unavailable; login will continue: {}", root(e).getMessage());
        }
    }

    private static Object call(Class<?> type, Object target, String name, Class<?>[] parameterTypes, Object... args)
            throws Exception {
        return type.getMethod(name, parameterTypes).invoke(target, args);
    }

    private static Throwable root(Throwable e) {
        while (e.getCause() != null) {
            e = e.getCause();
        }
        return e;
    }
}
