package api;

import handler.AuthorizationGrandTypeHandler;
import model.AppDataRepository;
import model.Client;

import javax.enterprise.inject.Instance;
import javax.enterprise.inject.literal.NamedLiteral;
import javax.inject.Inject;
import javax.json.Json;
import javax.json.JsonObject;
import javax.ws.rs.*;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;


@Path("token")
public class TokenEndPoint {
    private List<String> supportedGrandTypes = Arrays.asList("authorization_code", "refresh_token");

    @Inject
    private AppDataRepository appDataRepository;

    @Inject
    Instance<AuthorizationGrandTypeHandler> authorizationGrandTypeHandlers;

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response token(MultivaluedMap<String, String> params, @HeaderParam(HttpHeaders.AUTHORIZATION) String authHeader) throws Exception {
        String grantType = params.getFirst("grant_type");
        if (grantType == null || grantType.isEmpty()) {
            return responseError("Invalid Request", "grant_type is required", Response.Status.BAD_REQUEST);
        }

        if (!supportedGrandTypes.contains(grantType)) {
            return responseError("unsupported_grant_type", "grant_type should be one of: " + supportedGrandTypes, Response.Status.BAD_REQUEST);
        }

        // Client Authentication
        String[] clientCredentials = extract(authHeader);
        if (clientCredentials.length != 2) {
            return responseError("invalid_request", "Bad credentials client_id/client_secret", Response.Status.BAD_REQUEST);
        }

        String clientId = clientCredentials[0];
        Client client = appDataRepository.getClient(clientId);
        if (client == null) {
            return responseError("invalid_request", "Invalid client_id", Response.Status.BAD_REQUEST);
        }

        String clientSecret = clientCredentials[1];
        if (!clientSecret.equals(client.getClientSecret())) {
            return responseError("invalid_request", "Invalid client_secret", Response.Status.UNAUTHORIZED);
        }

        AuthorizationGrandTypeHandler authorizationGrandTypeHandler = authorizationGrandTypeHandlers.select(NamedLiteral.of(grantType)).get();
        JsonObject tokenResponse = null;
        try {
            tokenResponse = authorizationGrandTypeHandler.createAccessToken(clientId, params);
        } catch (WebApplicationException e) {
            return e.getResponse();
        } catch (Exception e) {
            return responseError("invalid_request", "Can't get token", Response.Status.INTERNAL_SERVER_ERROR);
        }

        return Response.ok(tokenResponse)
                .header("Cache-Control", "no-store")
                .header("Pragma", "no-cache").build();
    }

    private String[] extract(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Basic ")) {
            return new String(Base64.getDecoder().decode(authHeader.substring(6))).split(":");
        }
        return new String[]{};
    }

    private Response responseError(String error, String errorDescription, Response.Status status) {
        JsonObject errorResponse = Json.createObjectBuilder()
                .add("error", error)
                .add("error_description", errorDescription)
                .build();

        return Response.status(status).entity(errorResponse).build();
    }
}
