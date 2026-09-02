/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import org.apache.logging.log4j.LogManager;

import java.util.ArrayList;
import java.util.List;

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

        // Resolve by SUBJECT as well, but only when the username lookup did not
        // already land on an account carrying this binding. That keeps the scan
        // off the ordinary returning login — by far the common case — while
        // still covering the two states a username lookup alone cannot see: the
        // IdP renamed someone (no account under the new name, one bound under
        // the old), and a rename whose target name belongs to somebody else.
        String boundOnMatch = user == null ? null : users.getUserPreference(user.getId(), BINDING);
        if (!identity.subject().equals(boundOnMatch)) {
            User boundElsewhere = findBySubject(identity.subject(), config);
            // equals, not !=: getId() is an Integer, and Java compares two boxed
            // operands by reference — above the 127 cache, two objects for the
            // same row would read as different accounts and this would refuse a
            // legitimate login as a collision.
            if (boundElsewhere != null && (user == null || !boundElsewhere.getId().equals(user.getId()))) {
                if (user != null) {
                    // The subject belongs to one account and the username now
                    // belongs to another. Renaming would collide; merging two
                    // identities is not a decision to make during a login.
                    throw new SecurityException("OIDC username is already taken by another account");
                }
                // The subject binding is authoritative, so the account follows
                // the IdP's new name for it.
                String previous = boundElsewhere.getUsername();
                boundElsewhere.setUsername(identity.username());
                users.updateUser(boundElsewhere);
                LogManager.getLogger(UserProvisioner.class)
                        .info("OIDC renamed user '{}' to '{}' (same subject binding)", previous, identity.username());
                user = users.getUser(null, identity.username());
                if (user == null) {
                    throw new SecurityException("Could not rename the bound account");
                }
            }
        }

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

        // AFTER the binding checks, never before. Run earlier, this wrote the
        // token's profile onto whatever account matched the claimed username —
        // so anyone the IdP will issue for could set preferred_username=admin
        // and overwrite the real administrator's name, email and organization on
        // a login the engine then refused. A write on the unauthorized path.
        if (!created) {
            refreshProfile(user, identity);
        }
        settleFirstLogin(user);
        return new Result(user, created);
    }

    /**
     * The account already bound to this {@code issuer#subject}, or null. Scans
     * the user list because the engine offers no index on preferences — fine at
     * the scale an engine's user table runs to, and it only happens on the miss
     * path, i.e. a first login or a rename.
     */
    private User findBySubject(String subject, OidcConfig config) {
        List<User> matches = new ArrayList<>();
        try {
            for (User candidate : users.getAllUsers()) {
                if (subject.equals(users.getUserPreference(candidate.getId(), BINDING))) {
                    matches.add(candidate);
                }
            }
        } catch (Exception e) {
            LogManager.getLogger(UserProvisioner.class)
                    .warn("Could not search OIDC subject bindings: {}", e.getMessage());
            // "Could not search" is NOT "no match". Treating them alike sends a
            // renamed user down the JIT branch, which creates a second account
            // bound to the same subject — the exact forking this lookup exists
            // to prevent, now triggered by a transient database problem. Only
            // JIT can do that damage, so only JIT is refused here; with JIT off
            // the fall-through is a refused login either way.
            if (config.jitEnabled()) {
                throw new SecurityException("Could not verify the OIDC account binding");
            }
            return null;
        }
        if (matches.size() > 1) {
            // Exactly the state a pre-fix deployment leaves behind. Picking one
            // would rename an arbitrary account — possibly the less privileged —
            // and leave the other still bound under its old name.
            LogManager.getLogger(UserProvisioner.class).error(
                    "OIDC subject {} is bound to {} accounts ({}); refusing until an administrator resolves it",
                    subject, matches.size(), matches.stream().map(User::getUsername).toList());
            throw new SecurityException("OIDC subject is bound to more than one account");
        }
        return matches.isEmpty() ? null : matches.get(0);
    }

    /**
     * Copies IdP-owned profile fields onto a returning user. Only writes when
     * something actually differs, so an unchanged login costs one comparison
     * rather than a database write, and only overwrites fields the token
     * actually carried — a claim the IdP does not send must not blank the
     * engine's copy.
     */
    private void refreshProfile(User user, ClaimsMapper.Identity identity) {
        try {
            User incoming = identity.profile();
            boolean changed = false;
            changed |= apply(incoming.getEmail(), user.getEmail(), user::setEmail);
            changed |= apply(incoming.getFirstName(), user.getFirstName(), user::setFirstName);
            changed |= apply(incoming.getLastName(), user.getLastName(), user::setLastName);
            changed |= apply(incoming.getOrganization(), user.getOrganization(), user::setOrganization);
            if (changed) {
                users.updateUser(user);
            }
        } catch (Exception e) {
            // Cosmetic, like the first-login flag: a stale display name must
            // never fail an otherwise valid login.
            LogManager.getLogger(UserProvisioner.class)
                    .warn("Could not refresh the profile for '{}': {}", user.getUsername(), e.getMessage());
        }
    }

    private static boolean apply(String incoming, String current, java.util.function.Consumer<String> setter) {
        if (incoming == null || incoming.isBlank() || incoming.equals(current)) {
            return false;
        }
        setter.accept(incoming);
        return true;
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
