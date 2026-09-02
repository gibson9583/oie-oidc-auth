/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import java.util.Properties;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

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

    public OidcAdminServlet(@Context HttpServletRequest request, @Context SecurityContext sc) {
        super(request, sc, PLUGIN_POINT, !isPublicPath(request));
    }

    /** Trailing-slash tolerant: {@code /public/} must stay pre-auth too. */
    private static boolean isPublicPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        while (uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        return uri.endsWith("/public");
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
            out.put("discoveryUrl", config.discoveryUrl());
            out.put("clientId", config.clientId());
        }
        return out.toString();
    }

    @Override
    public String configuration() throws ClientException {
        try {
            // Live policy + operator pins — what the engine actually enforces.
            Properties effective = OidcConfigLoader.withOverrides(OidcAuthorizationPlugin.currentProperties());
            ObjectNode out = toNode(effective);
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
            // The one value IdP setup needs and the tab never showed, sending
            // operators to the README mid-task.
            out.put("_redirectUri", "<web-administrator-origin>/oidc/callback");
            // Which keys an operator pinned via OIE_OIDC_* / system property.
            // Those win over anything saved here, so a field the form appears to
            // control but cannot is worth naming rather than letting someone
            // edit it repeatedly and watch it revert.
            for (String key : OidcConfigLoader.pinned()) {
                out.withArray("_pinned").add(key);
            }
            return JSON.writeValueAsString(out);
        } catch (Exception e) {
            throw failure("read", e);
        }
    }

    @Override
    public void configuration(String body) throws ClientException {
        try {
            // Merge over the live policy: setPluginProperties REPLACES the whole
            // group, so whatever is handed to it becomes the policy — a body
            // carrying only some keys must update those and leave the rest, not
            // blank them. The base is the STORED policy, never the overlaid one:
            // an operator pin overlays at apply time and is never persisted.
            Properties stored = OidcAuthorizationPlugin.currentProperties();
            Properties properties = new Properties();
            properties.putAll(stored);
            Properties incoming = OidcConfigLoader.fromJson(body);
            // Belt and braces: fromJson already whitelists to catalogued keys, so
            // the reserved "_" reporting keys cannot reach here. Kept so the
            // invariant is stated where it matters rather than inferred.
            incoming.stringPropertyNames().stream().filter(k -> k.startsWith("_")).forEach(incoming::remove);
            // Never persist a PINNED value. The GET serves effective values, so
            // the form is holding whatever an OIE_OIDC_* variable or system
            // property overrode — and saving would write that into the stored
            // policy. Nothing changes while the pin is in place, so the damage
            // is deferred and invisible: remove the variable later and the pin's
            // value has silently become permanent. Worst case is an operator
            // using OIE_OIDC_ENABLED=false as an emergency off, someone pressing
            // Save, and SSO switching itself back on when the variable is
            // cleared.
            for (String key : OidcConfigLoader.pinned()) {
                incoming.remove(key);
            }
            properties.putAll(incoming);
            OidcConfig.from(properties);   // validate BEFORE persisting
            OidcConfigLoader.saveAndApply(properties);
        } catch (Exception e) {
            throw failure("save", e);
        }
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
