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
        boolean configured = config != null && config.enabled();
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
            return JSON.writeValueAsString(
                    toNode(OidcConfigLoader.withOverrides(OidcAuthorizationPlugin.currentProperties())));
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
            Properties properties = new Properties();
            properties.putAll(OidcAuthorizationPlugin.currentProperties());
            properties.putAll(OidcConfigLoader.fromJson(body));
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
            DiscoveryClient.Metadata metadata = new DiscoveryClient().get(config);
            ObjectNode out = JSON.createObjectNode();
            out.put("ok", true);
            out.put("issuer", metadata.issuer());
            out.put("jwksUri", metadata.jwksUri());
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
