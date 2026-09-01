/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import org.apache.logging.log4j.LogManager;

import com.mirth.connect.model.User;
import com.mirth.connect.server.controllers.UserController;

/**
 * Resolves the ID-token identity to an engine user row, JIT-provisioning when
 * allowed, and enforces subject binding against local-account takeover:
 *
 * <ul>
 *   <li>Every OIDC-managed account is permanently bound to {@code issuer#subject}
 *       (stored as the {@code oidc.subject} user preference on first login).</li>
 *   <li>An EXISTING account with no binding (e.g. a local admin) is refused
 *       unless the operator explicitly listed it in {@code linked-accounts} —
 *       an IdP username collision must never inherit local privileges.</li>
 *   <li>A binding mismatch (the IdP recycled a username for a new person) is
 *       refused outright.</li>
 * </ul>
 */
public final class UserProvisioner {

    static final String BINDING = "oidc.subject";

    /**
     * The engine's "this user has not completed first-login setup" flag. Clients
     * read it to decide whether to run the setup wizard (Swing's
     * FirstLoginDialog, the web client's Welcome modal), which REQUIRES the user
     * to choose a password — meaningless for an account whose credentials live
     * at the IdP, and misleading: the password it sets is an engine-local one
     * that SSO never consults.
     */
    static final String FIRST_LOGIN = "firstlogin";

    private final UserController users;

    public UserProvisioner(UserController users) {
        this.users = users;
    }

    public record Result(User user, boolean created) {}

    public Result provision(ClaimsMapper.Identity identity, OidcConfig config) throws Exception {
        User user = users.getUser(null, identity.username());
        boolean created = false;
        if (user == null) {
            if (!config.jitEnabled()) {
                throw new SecurityException("User is not authorized for this engine");
            }
            try {
                users.updateUser(identity.profile());   // id == null → insert
            } catch (Exception race) {
                // Two first logins racing the same insert: whoever lost still
                // finds the row below.
            }
            user = users.getUser(null, identity.username());
            if (user == null) {
                throw new SecurityException("Could not provision user");
            }
            created = true;
        }

        String bound = users.getUserPreference(user.getId(), BINDING);
        String explicit = config.linkedAccounts().get(identity.username());
        if (bound == null || bound.isBlank()) {
            if (!created && !identity.subject().equals(explicit)) {
                throw new SecurityException("Existing account is not linked for OIDC");
            }
            users.setUserPreference(user.getId(), BINDING, identity.subject());
        } else if (!bound.equals(identity.subject())) {
            throw new SecurityException("OIDC subject binding mismatch");
        }
        settleFirstLogin(user);
        return new Result(user, created);
    }

    /**
     * Marks first-login setup complete for an OIDC-managed account, so no client
     * asks an SSO user to choose an engine password. Checked on every provision
     * rather than only at creation: accounts bound before this existed heal on
     * their next login. The read keeps it to one write per account, not one per
     * login.
     */
    private void settleFirstLogin(User user) {
        try {
            if (!"false".equalsIgnoreCase(users.getUserPreference(user.getId(), FIRST_LOGIN))) {
                users.setUserPreference(user.getId(), FIRST_LOGIN, "false");
            }
        } catch (Exception e) {
            // Cosmetic: a stray setup wizard must never fail an otherwise good login.
            LogManager.getLogger(UserProvisioner.class)
                    .warn("Could not clear the first-login flag for '{}': {}", user.getUsername(), e.getMessage());
        }
    }
}
