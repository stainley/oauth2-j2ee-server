package handler;


import javax.json.JsonObject;
import javax.ws.rs.core.MultivaluedMap;

public interface AuthorizationGrandTypeHandler {
    JsonObject createAccessToken(String userId, MultivaluedMap<String, String> params) throws Exception;
}
