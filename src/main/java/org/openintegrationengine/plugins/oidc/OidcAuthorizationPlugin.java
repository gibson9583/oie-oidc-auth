/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HexFormat;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.mirth.connect.client.core.ControllerException;
import com.mirth.connect.client.core.api.util.OperationUtil;
import com.mirth.connect.model.ExtensionPermission;
import com.mirth.connect.model.LoginStatus;
import com.mirth.connect.model.LoginStatus.Status;
import com.mirth.connect.plugins.AuthorizationPlugin;
import com.mirth.connect.plugins.ServicePlugin;
import com.mirth.connect.server.controllers.UserController;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * The engine half of native web-client OIDC login. The web tier performs the
 * browser-facing Authorization Code + PKCE flow and hands the resulting ID
 * token to {@code POST /users/_login} as {@code password=oidc:<idToken>}; this
 * plugin fully re-validates the token, maps claims to an engine identity,
 * JIT-provisions when configured, syncs the RBAC role, and answers with the
 * derived username so the session — and every audited event — belongs to the
 * real named user.
 *
 * <p>Contract: an UNPREFIXED password returns {@code null} (fall through to
 * local auth, keeping engine lockout and the break-glass path); an
 * {@code oidc:}-prefixed password NEVER returns null — a failed SSO assertion
 * must not degrade into a password guess.</p>
 */
public final class OidcAuthorizationPlugin implements AuthorizationPlugin, ServicePlugin {

    public static final String PLUGIN_POINT = "OIDC Authentication";

    private static final Logger log = LogManager.getLogger(OidcAuthorizationPlugin.class);
    private static final int REPLAY_CACHE_LIMIT = 10000;
    private static final int THROTTLE_SWEEP_THRESHOLD = 1000;

    /** The live instance, so the admin servlet can apply a saved policy. */
    static volatile OidcAuthorizationPlugin instance;

    private volatile Properties properties = new Properties();
    private volatile OidcConfig config;
    private volatile OidcTokenValidator validator;
    /** Why the last apply() rejected the policy, or null if it took. */
    private volatile String lastError;
    private final ConcurrentMap<String, Long> seen = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Deque<Long>> attempts = new ConcurrentHashMap<>();
    private final ClaimsMapper mapper = new ClaimsMapper();
    private final RbacRoleAssigner roles = new RbacRoleAssigner();

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
        seen.clear();
        attempts.clear();
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

    private boolean disabled() {
        return killSwitchActive();
    }

    @Override
    public LoginStatus authorizeUser(String username, String password) throws ControllerException {
        if (password == null || !password.startsWith("oidc:")) {
            return null;   // not ours — local auth decides, with its own lockout
        }
        if (disabled() || config == null || !config.enabled()) {
            return fail("SSO is disabled on this engine.");
        }
        try {
            // This path bypasses the engine's per-user strike lockout, so it
            // carries its own throttle: per-hint and global.
            throttle("*");
            throttle(username);

            String token = password.substring(5);
            String tokenHash = hash(token);
            JWTClaimsSet claims = validator.validate(token);

            long now = System.currentTimeMillis();
            seen.entrySet().removeIf(entry -> entry.getValue() < now);
            if (seen.size() > REPLAY_CACHE_LIMIT) {
                throw new SecurityException("replay cache capacity reached");
            }
            if (seen.putIfAbsent(tokenHash, now + config.maxTokenAgeSeconds() * 1000) != null) {
                return fail("SSO assertion was already used.");
            }

            ClaimsMapper.Identity identity = mapper.map(claims, config);
            UserProvisioner.Result provisioned =
                    new UserProvisioner(UserController.getInstance()).provision(identity, config);
            roles.assign(provisioned.user().getId(), provisioned.created(), identity, config);
            log.info("OIDC login accepted for user '{}' subject hash {}", identity.username(), hash(identity.subject()));
            return new LoginStatus(Status.SUCCESS, null, identity.username());
        } catch (Throwable e) {
            // Throwable, not Exception. The contract above is that an oidc:
            // assertion NEVER falls out of this method — it fails closed, with a
            // status. An Error does not respect `catch (Exception)`: a
            // LinkageError from a half-installed dependency, raised while
            // resolving the user controller, would propagate into the engine's
            // login path instead of being refused here. Fail closed on anything.
            log.warn("OIDC login rejected for user hint '{}': {}", username, e.toString());
            return fail("SSO sign-in was rejected.");
        }
    }

    private void throttle(String key) {
        long now = System.currentTimeMillis();
        int limit = "*".equals(key) ? 300 : 20;
        // Keys are attacker-chosen (username hints), so the map itself needs a
        // bound: sweep emptied buckets once it grows. A racing computeIfAbsent
        // can lose one tick to the sweep — acceptable for a throttle.
        if (attempts.size() > THROTTLE_SWEEP_THRESHOLD) {
            attempts.entrySet().removeIf(entry -> {
                synchronized (entry.getValue()) {
                    entry.getValue().removeIf(time -> time < now - 60000);
                    return entry.getValue().isEmpty();
                }
            });
        }
        Deque<Long> bucket = attempts.computeIfAbsent(String.valueOf(key), k -> new ArrayDeque<>());
        synchronized (bucket) {
            while (!bucket.isEmpty() && bucket.peek() < now - 60000) {
                bucket.remove();
            }
            if (bucket.size() >= limit) {
                throw new SecurityException("too many attempts");
            }
            bucket.add(now);
        }
    }

    private LoginStatus fail(String message) {
        return new LoginStatus(Status.FAIL, message);
    }

    private String hash(String value) {
        try {
            return HexFormat.of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)))
                    .substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
