/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.util.Properties;
import java.util.function.Supplier;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.mirth.connect.client.core.ControllerException;
import com.mirth.connect.client.core.api.util.OperationUtil;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.LoginStatus.Status;
import com.mirth.connect.model.User;
import com.mirth.connect.plugins.AuthorizationPlugin;
import com.mirth.connect.plugins.ServicePlugin;
import com.mirth.connect.server.controllers.UserController;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * The engine half of the web administrator's OpenID Connect sign-in. The
 * engine runs the browser-facing flow itself ({@link OidcFlow}); its callback
 * validates the ID token, nonce included, and issues a one-time ticket that
 * the web client redeems through the engine's ordinary login as
 * {@code password=oidc:ticket:<id>}. This plugin turns the ticket back into
 * the validated token, maps claims to an engine identity, JIT-provisions when
 * configured, syncs the RBAC role, and answers with the derived username so
 * the session — and every audited event — belongs to the real named user.
 *
 * <p>Contract: an {@code oidc:}-prefixed password NEVER returns null — a
 * failed SSO assertion must not degrade into a password guess — and only a
 * ticket is a credential: a bare ID token, however obtained, is refused
 * without being examined. An UNPREFIXED password returns null (local auth
 * decides, with the engine's own lockout) unless the account is SSO-managed —
 * bound to a provider subject, not listed in {@code linked-accounts}, while
 * SSO is active — in which case it is refused: that account signs in through
 * the provider only, so removing it there removes its access here.</p>
 */
public final class OidcAuthorizationPlugin implements AuthorizationPlugin, ServicePlugin {

    public static final String PLUGIN_POINT = "OIDC Authentication";
    static final String CREDENTIAL_PREFIX = "oidc:";
    static final String TICKET_PREFIX = "ticket:";
    static final String SSO_MANAGED_MESSAGE = "This account signs in through SSO.";

    private static final Logger log = LogManager.getLogger(OidcAuthorizationPlugin.class);

    /** The live instance, so the admin servlet can apply a saved policy. */
    static volatile OidcAuthorizationPlugin instance;

    private volatile Properties properties = new Properties();
    private volatile OidcConfig config;
    private volatile OidcTokenValidator validator;
    /** Why the last apply() rejected the policy, or null if it took. */
    private volatile String lastError;
    private final ReplayCache replays = new ReplayCache();
    /** Validated tokens waiting to be redeemed through the engine's own login. */
    private final LoginTicketStore tickets = new LoginTicketStore();
    private final ClaimsMapper mapper = new ClaimsMapper();
    private final RbacRoleAssigner roles = new RbacRoleAssigner();
    /** The engine's user directory; replaceable so tests need no running engine. */
    private volatile Supplier<UserController> users = UserController::getInstance;

    @Override
    public String getPluginPointName() {
        return PLUGIN_POINT;
    }

    @Override
    public void init(Properties stored) {
        apply(stored);
    }

    @Override
    public void update(Properties stored) {
        apply(stored);
    }

    @Override
    public void start() {
        // Configuration arrived via init(); nothing to re-read.
    }

    @Override
    public void stop() {
        replays.clear();
        tickets.clear();
    }

    /** The live validator, for the sign-in flow; null while disabled or invalid. */
    static OidcTokenValidator currentValidator() {
        OidcAuthorizationPlugin current = instance;
        return current != null ? current.validator : null;
    }

    /** The live ticket store, for the sign-in flow's callback; null before init. */
    static LoginTicketStore currentTickets() {
        OidcAuthorizationPlugin current = instance;
        return current != null ? current.tickets : null;
    }

    @Override
    public Properties getDefaultProperties() {
        // The engine seeds these into the property store on first install and
        // merges newly added keys on upgrade — the native settings lifecycle.
        return OidcConfigLoader.defaults();
    }

    @Override
    public ExtensionPermission[] getExtensionPermissions() {
        return new ExtensionPermission[] { new ExtensionPermission(PLUGIN_POINT,
                OidcAdminServletInterface.PERMISSION_MANAGE,
                "Allows viewing, testing, and changing OIDC authentication policy.",
                OperationUtil.getOperationNamesForPermission(OidcAdminServletInterface.PERMISSION_MANAGE,
                        OidcAdminServletInterface.class),
                new String[] { "settings_OIDC Authentication/doSave" }) };
    }

    /**
     * The single configuration entry point, engine-pushed (init/update) or
     * servlet-pushed (save). The plugin never reads the property store; the
     * given properties — plus operator env/system pins — ARE the policy.
     */
    private void apply(Properties stored) {
        instance = this;
        Properties snapshot = new Properties();
        if (stored != null) {
            snapshot.putAll(stored);
        }
        properties = snapshot;
        try {
            config = OidcConfig.from(OidcConfigLoader.withOverrides(snapshot));
            validator = config.enabled() ? new OidcTokenValidator(config, new DiscoveryClient()) : null;
            // One line that answers "why is there no SSO button?" without a
            // debugger. That question has several causes — extension present but
            // policy off, policy rejected, emergency switch thrown, JIT on
            // without RBAC — and until now every one of them produced the same
            // silence, so the only way to tell them apart was to know about an
            // undocumented endpoint. Logged at startup and on every save.
            if (killSwitchActive()) {
                log.warn("OIDC authentication is SWITCHED OFF by OIE_OIDC_DISABLED (or the "
                        + "org.openintegrationengine.oidc.disabled system property). The stored policy is ignored and "
                        + "the web administrator is told SSO is unavailable.");
            } else if (!config.enabled()) {
                log.info("OIDC authentication is disabled (policy key 'enabled' is false). The web administrator will "
                        + "not offer an SSO button.");
            } else {
                log.info("OIDC authentication is ACTIVE for {} (client {}). JIT provisioning {}; role sync {}.",
                        config.discoveryUrl(), config.clientId(),
                        config.jitEnabled() ? "ON" : "off", config.rolesSync());
                if (config.jitEnabled() && !RbacRoleAssigner.isInstalled()) {
                    log.warn("OIDC JIT provisioning is ON and the role-based-access-control extension is NOT "
                            + "installed. The engine has no permission model without it, so every user this "
                            + "provisions will hold full administrative access on first sign-in.");
                }
            }
        } catch (Exception e) {
            config = null;
            validator = null;
            // Kept so the settings tab can SAY this, rather than showing the
            // stored properties as though they were in force. A policy that
            // fails to parse otherwise presents as healthy — "Enable OIDC login"
            // ticked — while the engine serves configured:false and every SSO
            // attempt is told the feature is switched off.
            lastError = e.getMessage() != null ? e.getMessage() : e.toString();
            log.warn("OIDC authentication is not configured: {}", e.getMessage());
            return;
        }
        lastError = null;
    }

    /** The active stored policy (pre-override), for the admin servlet's GET. */
    static Properties currentProperties() {
        OidcAuthorizationPlugin current = instance;
        return current != null ? current.properties : new Properties();
    }

    /** The active parsed config (or null when disabled/invalid), for /public. */
    static OidcConfig currentConfig() {
        OidcAuthorizationPlugin current = instance;
        return current != null ? current.config : null;
    }

    /**
     * The issuer the live validator has actually seen, or null before the first
     * sign-in. For the settings tab's linked accounts, which must carry the
     * token's exact {@code iss}. Read-only: nothing here fetches.
     */
    static String currentIssuer() {
        OidcAuthorizationPlugin current = instance;
        OidcTokenValidator live = current != null ? current.validator : null;
        return live != null ? live.cachedIssuer() : null;
    }

    /** Why the stored policy is not in force, or null. For the settings tab. */
    static String currentError() {
        OidcAuthorizationPlugin current = instance;
        return current != null ? current.lastError : null;
    }

    /**
     * Whether the emergency switch is on. Static so the servlet can report it:
     * the switch is checked per login, but a login screen that keeps offering
     * SSO while every attempt is refused is the wrong way to find that out.
     */
    static boolean killSwitchActive() {
        return Boolean.getBoolean("org.openintegrationengine.oidc.disabled")
                || "true".equalsIgnoreCase(System.getenv("OIE_OIDC_DISABLED"));
    }

    static void applyToInstance(Properties stored) {
        OidcAuthorizationPlugin current = instance;
        if (current != null) {
            current.apply(stored);
        }
    }

    /** Test seam: inject a policy without touching the filesystem. */
    void configure(OidcConfig config, OidcTokenValidator validator) {
        this.config = config;
        this.validator = validator;
    }

    /** Test seam: a policy plus a user directory, so no engine is needed. */
    void configure(OidcConfig config, OidcTokenValidator validator, UserController users) {
        configure(config, validator);
        this.users = () -> users;
    }

    /** Test seam: the store the callback issues tickets into. */
    LoginTicketStore tickets() {
        return tickets;
    }

    /**
     * How long a spent token must be remembered: as long as the validator
     * would still accept it. The freshness window is
     * {@code iat >= now - (maxAge + skew)}, so a record kept for {@code maxAge}
     * alone left the final {@code skew} seconds of a token's life replayable.
     */
    static long replayTtlMillis(OidcConfig config) {
        return (config.maxTokenAgeSeconds() + config.clockSkewSeconds()) * 1000L;
    }

    private boolean disabled() {
        return killSwitchActive();
    }

    @Override
    public LoginStatus authorizeUser(String username, String password) throws ControllerException {
        if (password == null || !password.startsWith(CREDENTIAL_PREFIX)) {
            // Not ours — local auth decides, with its own lockout — unless the
            // account belongs to the provider.
            return ssoManaged(username) ? fail(SSO_MANAGED_MESSAGE) : null;
        }
        if (disabled() || config == null || !config.enabled()) {
            return fail("SSO is disabled on this engine.");
        }
        try {
            String credential = password.substring(CREDENTIAL_PREFIX.length());
            if (!credential.startsWith(TICKET_PREFIX)) {
                // Only a ticket is a credential. A bare ID token — out of a
                // provider's debug log, from another application sharing the
                // client, minted by some other flow — carries no nonce for an
                // attempt this engine made, and accepting it would make every
                // route that never touched /start a way in. Refused unread, so
                // there is nothing here for a guess to exercise.
                return fail("SSO sign-in was rejected.");
            }
            LoginTicketStore.Ticket ticket =
                    tickets.redeem(credential.substring(TICKET_PREFIX.length()), System.currentTimeMillis());
            if (ticket == null) {
                return fail("SSO sign-in expired or was already used. Try again.");
            }
            // The token behind the ticket passed validation, nonce included, in
            // the callback that issued it. Checking it again costs one cached
            // signature verification and catches a token that expired during
            // the minute a ticket may wait.
            String token = ticket.token();
            JWTClaimsSet claims = validator.validate(token);
            // Only AFTER the token proves valid: recording an unverified string
            // would let anyone fill the cache with garbage, and the capacity
            // guard refuses logins when full. A ticket is single-use, so this is
            // the backstop for the day two tickets are issued for one token.
            if (!replays.claim(token, replayTtlMillis(config), System.currentTimeMillis())) {
                return fail("SSO assertion was already used.");
            }

            ClaimsMapper.Identity identity = mapper.map(claims, config);
            UserProvisioner.Result provisioned = new UserProvisioner(users.get()).provision(identity, config);
            roles.assign(provisioned.user().getId(), provisioned.created(), identity, config);
            // The engine's own event log records every login; this is for a
            // debugger, not an operator's log.
            log.debug("OIDC login accepted for user '{}'", identity.username());
            return new LoginStatus(Status.SUCCESS, null, identity.username());
        } catch (Throwable e) {
            // Throwable, not Exception. The contract above is that an oidc:
            // assertion NEVER falls out of this method — it fails closed, with a
            // status. An Error does not respect `catch (Exception)`: a
            // LinkageError from a half-installed dependency, raised while
            // resolving the user controller, would propagate into the engine's
            // login path instead of being refused here. Fail closed on anything.
            log.warn("OIDC login rejected: {}", e.toString());
            return fail("SSO sign-in was rejected.");
        }
    }

    /**
     * Whether a local-password sign-in for this username must be refused
     * because the account belongs to the identity provider: bound to a subject
     * on an earlier SSO sign-in and not named in {@code linked-accounts}. Only
     * while SSO is ACTIVE — with the policy off or the emergency switch thrown,
     * the local password is the only way in and must keep working; that is
     * what the switch is for. Accounts in {@code linked-accounts} keep both
     * routes by the operator's explicit decision. Without this, anyone who
     * could set an engine password for a JIT-created account — the user
     * themselves, through their own profile — kept a way in after the
     * provider removed them. A lookup that fails answers "not managed": a
     * database hiccup inside an authorization plugin must not lock the
     * administrator out of the engine.
     */
    private boolean ssoManaged(String username) {
        OidcConfig active = config;
        if (username == null || disabled() || active == null || !active.enabled()
                || active.linkedAccounts().containsKey(username)) {
            return false;
        }
        try {
            UserController directory = users.get();
            User user = directory.getUser(null, username);
            if (user == null) {
                return false;
            }
            String bound = directory.getUserPreference(user.getId(), UserProvisioner.BINDING);
            return bound != null && !bound.isBlank();
        } catch (Throwable e) {
            log.warn("OIDC could not check whether '{}' is an SSO-managed account; local sign-in proceeds: {}",
                    username, e.toString());
            return false;
        }
    }

    private LoginStatus fail(String message) {
        return new LoginStatus(Status.FAIL, message);
    }

}
