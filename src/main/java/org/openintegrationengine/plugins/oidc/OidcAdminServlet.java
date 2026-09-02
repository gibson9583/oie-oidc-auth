/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.util.Properties;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.server.api.DontCheckAuthorized;
import com.mirth.connect.server.api.MirthServlet;

/**
 * Web-managed OIDC policy over the engine's native plugin-properties
 * lifecycle: GET serves the LIVE plugin's in-memory policy, PUT validates,
 * persists through the engine, and applies to the live plugin in one step —
 * the property store is never read at request time. Authentication is decided
 * per operation — {@code /public} is deliberately pre-login so the web tier
 * can decide whether to advertise SSO, while the configuration operations
 * carry {@code manageOIDC} and are enforced by the invocation handler.
 */
public final class OidcAdminServlet extends MirthServlet implements OidcAdminServletInterface {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Logger log = LogManager.getLogger(OidcAdminServlet.class);
    private static final String TXN_COOKIE = "oie-oidc-txn";
    /** One HTTP client for the token exchanges; the flow itself is stateless. */
    private static final OidcFlow FLOW = new OidcFlow();
    /** The callback is pre-auth and costs an outbound exchange; bound how fast it can be driven. */
    private static final FlowThrottle THROTTLE = new FlowThrottle();

    private final HttpServletResponse response;

    public OidcAdminServlet(@Context HttpServletRequest request, @Context SecurityContext sc,
            @Context HttpServletResponse response) {
        super(request, sc, PLUGIN_POINT, !isPublicPath(request));
        this.response = response;
    }

    /**
     * The three pre-auth operations: what the login screen asks before anyone is
     * signed in. Trailing-slash tolerant, so {@code /public/} stays pre-auth too.
     */
    private static boolean isPublicPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        while (uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        return uri.endsWith("/public") || uri.endsWith("/start") || uri.endsWith("/callback");
    }

    @Override
    @DontCheckAuthorized
    public String publicConfiguration() throws ClientException {
        ObjectNode out = JSON.createObjectNode();
        OidcConfig config = OidcAuthorizationPlugin.currentConfig();
        // The kill switch counts here, not just at login. It is checked per
        // authorization attempt, so without this the web login screen kept
        // offering the SSO button — advertising a path where every attempt is
        // refused — which is the opposite of what an emergency switch is for.
        boolean configured = !OidcAuthorizationPlugin.killSwitchActive() && config != null && config.enabled();
        out.put("configured", configured);
        if (configured) {
            // What the login card needs to draw the button, and nothing else:
            // the provider and client are the engine's business now that it
            // runs the flow, and this answers anyone who asks.
            out.put("providerLabel", config.providerLabel());
            out.put("autoRedirect", config.autoRedirect());
        }
        return out.toString();
    }

    /* ---- the browser-facing sign-in flow, run by the engine ---------------- */

    @Override
    @DontCheckAuthorized
    public String start(String body) throws ClientException {
        try {
            OidcConfig config = OidcAuthorizationPlugin.currentConfig();
            OidcTokenValidator validator = OidcAuthorizationPlugin.currentValidator();
            if (OidcAuthorizationPlugin.killSwitchActive() || config == null || !config.enabled() || validator == null) {
                return result(false, "SSO is disabled on this engine.");
            }
            JsonNode in = flowBody(body);
            DiscoveryClient.Metadata metadata = validator.discovery().get(config);
            OidcFlow.Start started = FLOW.start(config, metadata, in.path("return").asText("/"),
                    "login".equals(in.path("prompt").asText("")), System.currentTimeMillis());
            setTransactionCookie(started.sealed(), config, OidcTransaction.TTL_MILLIS / 1000);
            ObjectNode out = JSON.createObjectNode();
            out.put("ok", true);
            out.put("authorizeUrl", started.authorizeUrl());
            return out.toString();
        } catch (Exception e) {
            log.warn("OIDC sign-in could not start: {}", e.toString());
            return result(false, "SSO is unavailable. Use local sign-in.");
        }
    }

    @Override
    @DontCheckAuthorized
    public String callback(String body) throws ClientException {
        String sealed = transactionCookie();
        OidcConfig config = OidcAuthorizationPlugin.currentConfig();
        // One attempt per seal, whatever happens next: a cookie that survived a
        // failure could otherwise be retried with a different code.
        clearTransactionCookie(config);
        try {
            THROTTLE.hit(FlowThrottle.clientOf(request.getHeader("X-Forwarded-For"), request.getRemoteAddr()),
                    System.currentTimeMillis());
            OidcTokenValidator validator = OidcAuthorizationPlugin.currentValidator();
            LoginTicketStore tickets = OidcAuthorizationPlugin.currentTickets();
            if (OidcAuthorizationPlugin.killSwitchActive() || config == null || !config.enabled() || validator == null
                    || tickets == null) {
                return result(false, "SSO is disabled on this engine.");
            }
            JsonNode in = flowBody(body);
            if (!in.path("error").asText("").isBlank()) {
                return result(false, "The identity provider declined sign-in.");
            }
            DiscoveryClient.Metadata metadata = validator.discovery().get(config);
            OidcFlow.Completion done = FLOW.complete(config, metadata, validator, sealed,
                    in.path("code").asText(null), in.path("state").asText(null), System.currentTimeMillis());
            long now = System.currentTimeMillis();
            ObjectNode out = JSON.createObjectNode();
            out.put("ok", true);
            out.put("ticket", tickets.issue(done.idToken(), now));
            out.put("returnPath", done.returnPath());
            return out.toString();
        } catch (Exception e) {
            log.warn("OIDC sign-in could not complete: {}", e.toString());
            return result(false, "SSO sign-in could not be completed. Try again, or use local sign-in.");
        }
    }

    /** The flow's bodies are small JSON objects, possibly wrapped by the engine's String envelope. */
    private static JsonNode flowBody(String body) throws Exception {
        JsonNode node = JSON.readTree(body == null || body.isBlank() ? "{}" : body);
        if (node.isObject() && node.size() == 1 && node.path("string").isTextual()) {
            node = JSON.readTree(node.get("string").asText());
        }
        return node.isObject() ? node : JSON.createObjectNode();
    }

    private static String result(boolean ok, String message) {
        ObjectNode out = JSON.createObjectNode();
        out.put("ok", ok);
        out.put("message", message);
        return out.toString();
    }

    private String transactionCookie() {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (TXN_COOKIE.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * HttpOnly and SameSite=Lax; Secure whenever the web administrator is
     * reached over HTTPS. Path=/ rather than this servlet's path so it does not
     * depend on how the engine API is mounted in front of the browser.
     */
    private void setTransactionCookie(String value, OidcConfig config, long maxAgeSeconds) {
        boolean secure = config != null && config.webAdministratorUrl().startsWith("https://");
        response.addHeader("Set-Cookie", TXN_COOKIE + "=" + value + "; Path=/; HttpOnly; SameSite=Lax; Max-Age="
                + maxAgeSeconds + (secure ? "; Secure" : ""));
    }

    private void clearTransactionCookie(OidcConfig config) {
        setTransactionCookie("", config, 0);
    }

    @Override
    public String configuration() throws ClientException {
        try {
            // Live policy + operator pins — what the engine actually enforces.
            Properties effective = OidcConfigLoader.withOverrides(OidcAuthorizationPlugin.currentProperties());
            ObjectNode out = toNode(effective);
            // A secret is never echoed. The tab shows the mask, and merge() below
            // treats the mask coming back as "leave it".
            for (PolicySchema.Key key : PolicySchema.KEYS) {
                if (key.kind() == PolicySchema.Kind.SECRET && !effective.getProperty(key.name(), "").isEmpty()) {
                    out.put(key.name(), PolicySchema.SECRET_MASK);
                }
            }
            // Reserved keys carrying EFFECTIVE state, which the stored properties
            // cannot express. Without them the tab shows a policy that parsed and
            // applied — "Enable OIDC login" ticked — in exactly the two cases
            // where it did not: an emergency switch thrown outside the UI, and a
            // policy the engine rejected at load. Prefixed so they cannot
            // collide with a policy key, and stripped again on save.
            out.put("_killSwitch", OidcAuthorizationPlugin.killSwitchActive());
            String error = OidcAuthorizationPlugin.currentError();
            if (error != null) {
                out.put("_error", error);
            }
            // The one value IdP setup needs. Built from the stored web
            // administrator URL — shown even while the policy is off or
            // rejected, because registering it at the provider comes first.
            String base = effective.getProperty("web-administrator-url", "").trim().replaceAll("/+$", "");
            out.put("_redirectUri", (base.isEmpty() ? "<web-administrator-url>" : base) + OidcFlow.CALLBACK_PATH);
            // The issuer as the engine has actually seen it, once any sign-in has
            // fetched discovery. A linked account's value is issuer#subject and
            // must match the token's iss byte for byte; deriving it from the
            // discovery URL is wrong for some providers, so the tab only ever
            // offers this — and offers nothing before the engine knows.
            String issuer = OidcAuthorizationPlugin.currentIssuer();
            if (issuer != null) {
                out.put("_issuer", issuer);
            }
            // Which keys an operator pinned via OIE_OIDC_* / system property.
            // Those win over anything saved here, so a field the form appears to
            // control but cannot is worth naming rather than letting someone
            // edit it repeatedly and watch it revert.
            for (String key : OidcConfigLoader.pinned()) {
                out.withArray("_pinned").add(key);
            }
            // The schema itself, so the tab renders from the same declaration the
            // engine validates against. Previously the tab kept its own field
            // list, which is how it came to honour pinning on a third of its
            // controls: the list and the pin logic were maintained by hand, in
            // two places, and quietly disagreed.
            for (PolicySchema.Key key : PolicySchema.KEYS) {
                ObjectNode field = out.withArray("_schema").addObject();
                field.put("key", key.name());
                field.put("label", key.label());
                field.put("kind", key.kind().name().toLowerCase(java.util.Locale.ROOT));
                if (!key.choices().isEmpty()) {
                    key.choices().forEach(choice -> field.withArray("choices").add(choice));
                }
            }
            return JSON.writeValueAsString(out);
        } catch (Exception e) {
            throw failure("read", e);
        }
    }

    @Override
    public void configuration(String body) throws ClientException {
        try {
            // The ONLY route to saveAndApply, and merge() validates, so a policy
            // the engine would reject cannot reach the property store.
            OidcConfigLoader.saveAndApply(merge(OidcAuthorizationPlugin.currentProperties(), body));
        } catch (Exception e) {
            throw failure("save", e);
        }
    }

    /**
     * What a save actually writes. Extracted from {@link #configuration(String)}
     * so it can be exercised directly: this servlet cannot be constructed
     * without a JAX-RS request context, and the tests that tried to work around
     * that by restating these rules proved only that the copy in the test file
     * agreed with itself — all three could be neutered here with the suite
     * green. One implementation, called by both.
     */
    static Properties merge(Properties stored, String body) throws Exception {
        // Merge over the live policy: setPluginProperties REPLACES the whole
        // group, so whatever is handed to it becomes the policy — a body
        // carrying only some keys must update those and leave the rest, not
        // blank them. The base is the STORED policy, never the overlaid one:
        // an operator pin overlays at apply time and is never persisted.
        Properties properties = new Properties();
        properties.putAll(stored);
        // Whitelisted to catalogued keys, so the reserved "_" reporting keys the
        // GET adds cannot arrive here as policy however the form round-trips.
        Properties incoming = OidcConfigLoader.fromJson(body);
        // The mask the GET served for a secret is not a value. A form that
        // round-trips it untouched means "keep what is stored".
        for (PolicySchema.Key key : PolicySchema.KEYS) {
            if (key.kind() == PolicySchema.Kind.SECRET && PolicySchema.SECRET_MASK.equals(incoming.getProperty(key.name()))) {
                incoming.remove(key.name());
            }
        }
        // Never persist a PINNED value. The GET serves effective values, so
        // the form is holding whatever an OIE_OIDC_* variable or system
        // property overrode — and saving would write that into the stored
        // policy. Nothing changes while the pin is in place, so the damage
        // is deferred and invisible: remove the variable later and the pin's
        // value has silently become permanent. Worst case is an operator
        // using OIE_OIDC_ENABLED=false as an emergency off, someone pressing
        // Save, and SSO switching itself back on when the variable is cleared.
        for (String key : OidcConfigLoader.pinned()) {
            incoming.remove(key);
        }
        properties.putAll(incoming);
        OidcConfig.from(properties);   // validate BEFORE persisting
        return properties;
    }

    @Override
    public String test(String body) throws ClientException {
        try {
            OidcConfig config = OidcConfig.from(OidcConfigLoader.fromJson(body));
            DiscoveryClient discovery = new DiscoveryClient();
            DiscoveryClient.Metadata metadata = discovery.get(config);
            // Also fetch the key set. Discovery only proves the document parses;
            // signature verification needs the JWKS, so a test that skipped it
            // could report success against a provider whose keys are unreachable
            // and leave the first real login to find out.
            int keys = discovery.probeKeys(config, metadata);
            ObjectNode out = JSON.createObjectNode();
            out.put("ok", true);
            out.put("issuer", metadata.issuer());
            out.put("jwksUri", metadata.jwksUri());
            out.put("keyCount", keys);
            return out.toString();
        } catch (Exception e) {
            throw failure("test", e);
        }
    }

    private ObjectNode toNode(Properties properties) {
        ObjectNode node = JSON.createObjectNode();
        OidcConfigLoader.DEFAULTS.forEach(
                (key, fallback) -> node.put(key, properties.getProperty(key, fallback)));
        return node;
    }

    private ClientException failure(String action, Exception e) {
        return new ClientException("Failed to " + action + " OIDC configuration: " + e.getMessage(), e);
    }
}
