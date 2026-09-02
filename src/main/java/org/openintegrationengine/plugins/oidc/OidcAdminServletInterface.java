/*
 * OIE OIDC Authentication — engine-side OIDC login plugin.
 *
 * Published under the terms of the Mozilla Public License 2.0.
 */

package org.openintegrationengine.plugins.oidc;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import com.mirth.connect.client.core.ClientException;
import com.mirth.connect.client.core.api.BaseServletInterface;
import com.mirth.connect.client.core.api.MirthOperation;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;

/**
 * REST surface for the web-managed OIDC policy. Everything except the
 * deliberately narrow pre-auth {@code /public} endpoint carries the
 * {@code manageOIDC} extension permission — whoever holds it can repoint the
 * engine at any IdP, so grant it as carefully as user management itself.
 *
 * <p>String parameters and returns carry JSON TEXT; on the wire the engine's
 * serializer envelopes them as {@code {"string": "<json>"}} in both
 * directions.</p>
 */
@Path("/extensions/oidcauth")
@Tag(name = "Extension Services")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public interface OidcAdminServletInterface extends BaseServletInterface {

    String PLUGIN_POINT = "OIDC Authentication";
    String PERMISSION_MANAGE = "manageOIDC";

    @GET
    @Path("/public")
    @Operation(summary = "Returns non-secret OIDC login metadata.")
    @MirthOperation(name = "getOidcPublicConfiguration", display = "Get public OIDC configuration", auditable = false)
    String publicConfiguration() throws ClientException;

    @POST
    @Path("/start")
    @Operation(summary = "Begins a browser sign-in: seals the attempt in a cookie and returns the provider URL to open.")
    @MirthOperation(name = "startOidcLogin", display = "Start OIDC sign-in", auditable = false)
    String start(String json) throws ClientException;

    @POST
    @Path("/callback")
    @Operation(summary = "Completes a browser sign-in from the code and state the provider returned; answers with a one-time login ticket.")
    @MirthOperation(name = "completeOidcLogin", display = "Complete OIDC sign-in", auditable = false)
    String callback(String json) throws ClientException;

    @GET
    @Path("/configuration")
    @Operation(summary = "Returns the editable OIDC policy.")
    @MirthOperation(name = "getOidcConfiguration", display = "View OIDC configuration", permission = PERMISSION_MANAGE, auditable = false)
    String configuration() throws ClientException;

    @PUT
    @Path("/configuration")
    @Operation(summary = "Validates and saves the OIDC policy.")
    @MirthOperation(name = "setOidcConfiguration", display = "Manage OIDC configuration", permission = PERMISSION_MANAGE)
    void configuration(String json) throws ClientException;

    @POST
    @Path("/test")
    @Operation(summary = "Tests discovery and JWKS connectivity for the supplied policy.")
    @MirthOperation(name = "testOidcConfiguration", display = "Test OIDC configuration", permission = PERMISSION_MANAGE, auditable = false)
    String test(String json) throws ClientException;
}
