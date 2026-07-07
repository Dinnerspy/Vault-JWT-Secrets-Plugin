package io.jenkins.plugins.vault_jwt_secrets.vault;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultJwtConfig;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Minimal Vault REST client over the JDK HTTP client. Only what the plugin needs:
 * JWT login, KV v2 read, best-effort token revocation, and a health check.
 * JWTs, client tokens, and secret values are never logged.
 */
public final class VaultClient {

    private static final Logger LOGGER = Logger.getLogger(VaultClient.class.getName());
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final String baseUrl;
    private final @CheckForNull String namespace;
    private final String authPath;
    private final HttpClient http;

    public VaultClient(@NonNull VaultJwtConfig config) throws IOException {
        String url = config.getVaultUrl();
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Vault URL is not configured");
        }
        this.baseUrl = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
        this.namespace = config.getNamespace();
        this.authPath = trimSlashes(config.getEffectiveAuthPath());
        HttpClient.Builder builder =
                HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).followRedirects(HttpClient.Redirect.NEVER);
        SSLContext ssl = buildSslContext(config);
        if (ssl != null) {
            builder.sslContext(ssl);
        }
        this.http = builder.build();
    }

    /** Logs in via the JWT auth method and returns the Vault client token. */
    @NonNull
    public String loginWithJwt(@NonNull String jwt, @NonNull String role)
            throws VaultClientException, IOException, InterruptedException {
        ObjectNode body = JsonNodeFactory.instance.objectNode();
        body.put("jwt", jwt);
        body.put("role", role);
        String loginPath = "/v1/auth/" + authPath + "/login";
        HttpResponse<String> response = send(request(loginPath, null)
                .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                .build());
        if (response.statusCode() >= 500) {
            // one retry on server-side errors
            response = send(request(loginPath, null)
                    .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                    .build());
        }
        if (response.statusCode() != 200) {
            throw error("Vault JWT login (role '" + role + "')", response);
        }
        JsonNode token = JSON.readTree(response.body()).path("auth").path("client_token");
        if (!token.isTextual() || token.asText().isEmpty()) {
            throw new VaultClientException(
                    "Vault JWT login (role '" + role + "')",
                    response.statusCode(),
                    List.of("response contained no auth.client_token"));
        }
        return token.asText();
    }

    /** Reads a KV v2 secret and returns its fields. Values are stringified if not already text. */
    @NonNull
    public Map<String, String> readKvV2(@NonNull String clientToken, @NonNull KvV2Ref ref)
            throws VaultClientException, IOException, InterruptedException {
        HttpResponse<String> response =
                send(request(ref.apiPath(), clientToken).GET().build());
        if (response.statusCode() != 200) {
            throw error("Vault read of '" + ref + "'", response);
        }
        JsonNode data = JSON.readTree(response.body()).path("data").path("data");
        if (!data.isObject()) {
            throw new VaultClientException(
                    "Vault read of '" + ref + "'",
                    response.statusCode(),
                    List.of("response contained no data.data object — is '" + ref.mount() + "' a KV v2 mount?"));
        }
        Map<String, String> fields = new LinkedHashMap<>();
        data.fields()
                .forEachRemaining(e -> fields.put(
                        e.getKey(),
                        e.getValue().isTextual()
                                ? e.getValue().asText()
                                : e.getValue().toString()));
        return fields;
    }

    /** Revokes the client token. Best effort: failures are logged at FINE and never propagate. */
    public void revokeSelf(@NonNull String clientToken) {
        try {
            HttpResponse<String> response = send(request("/v1/auth/token/revoke-self", clientToken)
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build());
            if (response.statusCode() != 200 && response.statusCode() != 204) {
                LOGGER.log(Level.FINE, "Vault token revocation returned HTTP {0}", response.statusCode());
            }
        } catch (Exception x) {
            LOGGER.log(Level.FINE, "Vault token revocation failed", x);
        }
    }

    /** Checks reachability. Vault health returns 200/429/472/473 depending on standby/DR state. */
    public void healthCheck() throws VaultClientException, IOException, InterruptedException {
        HttpResponse<String> response =
                send(request("/v1/sys/health", null).GET().build());
        int status = response.statusCode();
        if (status != 200 && status != 429 && status != 472 && status != 473) {
            throw error("Vault health check", response);
        }
    }

    private HttpRequest.Builder request(String path, @CheckForNull String token) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path))
                .timeout(REQUEST_TIMEOUT)
                .header("Content-Type", "application/json")
                .header("X-Vault-Request", "true");
        if (namespace != null && !namespace.isBlank()) {
            b.header("X-Vault-Namespace", namespace);
        }
        if (token != null) {
            b.header("X-Vault-Token", token);
        }
        return b;
    }

    private HttpResponse<String> send(HttpRequest request) throws IOException, InterruptedException {
        return http.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static VaultClientException error(String operation, HttpResponse<String> response) {
        List<String> errors = new ArrayList<>();
        try {
            JsonNode node = JSON.readTree(response.body()).path("errors");
            if (node.isArray()) {
                node.forEach(e -> errors.add(e.asText()));
            }
        } catch (IOException ignored) {
            // non-JSON error body; report status only
        }
        return new VaultClientException(operation, response.statusCode(), errors);
    }

    private static String trimSlashes(String s) {
        String r = s;
        while (r.startsWith("/")) {
            r = r.substring(1);
        }
        while (r.endsWith("/")) {
            r = r.substring(0, r.length() - 1);
        }
        return r;
    }

    @CheckForNull
    private static SSLContext buildSslContext(VaultJwtConfig config) throws IOException {
        try {
            if (config.isSkipTlsVerify()) {
                SSLContext ssl = SSLContext.getInstance("TLS");
                ssl.init(null, new TrustManager[] {new TrustAllManager()}, new SecureRandom());
                return ssl;
            }
            String pem = config.getCaCertificatePem();
            if (pem == null || pem.isBlank()) {
                return null; // JVM default trust store
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Collection<? extends java.security.cert.Certificate> certs =
                    cf.generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            int i = 0;
            for (java.security.cert.Certificate cert : certs) {
                trustStore.setCertificateEntry("vault-ca-" + i++, cert);
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            SSLContext ssl = SSLContext.getInstance("TLS");
            ssl.init(null, tmf.getTrustManagers(), new SecureRandom());
            return ssl;
        } catch (java.security.GeneralSecurityException x) {
            throw new IOException("Could not set up TLS trust for Vault: " + x.getMessage(), x);
        }
    }

    @SuppressWarnings("lgtm[java/insecure-trustmanager]")
    private static final class TrustAllManager implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
