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
                // Say so, at WARN, naming the claim that was read and what came
                // back. Falling through to the default is the single most likely
                // misconfiguration in this extension and the hardest to see: a
                // roles.claim pointing at the wrong path — Keycloak puts realm
                // roles at realm_access.roles, and its mappers default to the
                // access token rather than the ID token — yields NO claim values
                // and therefore the default role for every user who signs in. If
                // that default is a privileged role, everyone becomes privileged,
                // and nothing else in the system remarks on it.
                if (identity.roles().isEmpty()) {
                    log.warn("OIDC found no values in the '{}' claim for user id {}; assigning the default role '{}'. "
                            + "If that is unexpected, check the claim path and that the provider's mapper adds it to "
                            + "the ID token (not only the access token).", config.rolesClaim(), userId, role);
                } else {
                    log.warn("OIDC matched none of the claim values {} to a role for user id {}; assigning the "
                            + "default role '{}'.", identity.roles(), userId, role);
                }
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
            // Only fires on an actual CHANGE (an unchanged role returned above),
            // so this is the audit line for "the IdP moved someone's access".
            log.info("OIDC assigned RBAC role '{}' to user id {}", role, userId);
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
