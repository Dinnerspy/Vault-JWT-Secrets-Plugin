package io.jenkins.plugins.vault_jwt_secrets;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Test helper to decode JWTs without a JOSE library. */
public final class JwtTestUtil {

    private static final ObjectMapper JSON = new ObjectMapper();

    private JwtTestUtil() {}

    public static JsonNode payload(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            throw new IllegalArgumentException("not a JWS compact serialization");
        }
        return JSON.readTree(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
    }

    public static JsonNode header(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        return JSON.readTree(new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8));
    }

    /** The {@code aud} claim, which jjwt serializes as a string or (for one value) a JSON array. */
    public static String audience(String jwt) throws Exception {
        JsonNode aud = payload(jwt).path("aud");
        if (aud.isArray()) {
            return aud.isEmpty() ? "" : aud.get(0).asText();
        }
        return aud.asText();
    }
}
