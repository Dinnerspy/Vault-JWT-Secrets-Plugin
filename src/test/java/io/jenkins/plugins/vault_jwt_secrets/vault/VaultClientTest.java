package io.jenkins.plugins.vault_jwt_secrets.vault;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultJwtConfig;
import java.util.Map;
import org.junit.jupiter.api.Test;

@WireMockTest
class VaultClientTest {

    @Test
    void loginSendsJwtAndRoleAndReturnsToken(WireMockRuntimeInfo wm) throws Exception {
        wm.getWireMock()
                .register(post(urlEqualTo("/v1/auth/jwt/login"))
                        .willReturn(aResponse().withStatus(200).withBody("{\"auth\":{\"client_token\":\"tok-123\"}}")));
        VaultClient client = new VaultClient(
                VaultJwtConfig.builder().vaultUrl(wm.getHttpBaseUrl()).build());
        String token = client.loginWithJwt("my.jwt.value", "my-role");
        assertEquals("tok-123", token);
        wm.getWireMock()
                .verifyThat(postRequestedFor(urlEqualTo("/v1/auth/jwt/login"))
                        .withRequestBody(equalToJson("{\"jwt\":\"my.jwt.value\",\"role\":\"my-role\"}")));
    }

    @Test
    void loginUsesConfiguredAuthPathAndNamespace(WireMockRuntimeInfo wm) throws Exception {
        wm.getWireMock()
                .register(post(urlEqualTo("/v1/auth/jwt-jenkins/login"))
                        .willReturn(aResponse().withStatus(200).withBody("{\"auth\":{\"client_token\":\"tok\"}}")));
        VaultClient client = new VaultClient(VaultJwtConfig.builder()
                .vaultUrl(wm.getHttpBaseUrl())
                .authPath("jwt-jenkins")
                .namespace("team-a")
                .build());
        client.loginWithJwt("jwt", "role");
        wm.getWireMock()
                .verifyThat(postRequestedFor(urlEqualTo("/v1/auth/jwt-jenkins/login"))
                        .withHeader("X-Vault-Namespace", equalTo("team-a")));
    }

    @Test
    void loginFailureCarriesVaultErrors(WireMockRuntimeInfo wm) throws Exception {
        wm.getWireMock()
                .register(post(urlEqualTo("/v1/auth/jwt/login"))
                        .willReturn(aResponse()
                                .withStatus(403)
                                .withBody("{\"errors\":[\"error validating token: invalid audience (aud) claim\"]}")));
        VaultClient client = new VaultClient(
                VaultJwtConfig.builder().vaultUrl(wm.getHttpBaseUrl()).build());
        VaultClientException x = assertThrows(VaultClientException.class, () -> client.loginWithJwt("jwt", "role"));
        assertEquals(403, x.getStatus());
        assertTrue(x.getMessage().contains("invalid audience"), x.getMessage());
        assertTrue(x.getMessage().contains("role"), x.getMessage());
    }

    @Test
    void readsKvV2AndStringifiesValues(WireMockRuntimeInfo wm) throws Exception {
        wm.getWireMock()
                .register(get(urlEqualTo("/v1/ops/data/production/db"))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withBody("{\"data\":{\"data\":{\"password\":\"hunter2\",\"port\":5432}}}")));
        VaultClient client = new VaultClient(
                VaultJwtConfig.builder().vaultUrl(wm.getHttpBaseUrl()).build());
        Map<String, String> data = client.readKvV2("tok", KvV2Ref.parse("production/db@ops", "secret"));
        assertEquals("hunter2", data.get("password"));
        assertEquals("5432", data.get("port"));
        wm.getWireMock()
                .verifyThat(getRequestedFor(urlEqualTo("/v1/ops/data/production/db"))
                        .withHeader("X-Vault-Token", equalTo("tok")));
    }

    @Test
    void readOfKvV1ShapeGivesHelpfulError(WireMockRuntimeInfo wm) throws Exception {
        wm.getWireMock()
                .register(get(urlEqualTo("/v1/legacy/data/app"))
                        .willReturn(aResponse().withStatus(200).withBody("{\"data\":{\"password\":\"x\"}}")));
        VaultClient client = new VaultClient(
                VaultJwtConfig.builder().vaultUrl(wm.getHttpBaseUrl()).build());
        VaultClientException x = assertThrows(
                VaultClientException.class, () -> client.readKvV2("tok", KvV2Ref.parse("app@legacy", "secret")));
        assertTrue(x.getMessage().contains("KV v2"), x.getMessage());
    }

    @Test
    void revokeIsBestEffort(WireMockRuntimeInfo wm) throws Exception {
        wm.getWireMock()
                .register(post(urlEqualTo("/v1/auth/token/revoke-self"))
                        .willReturn(aResponse().withStatus(500)));
        VaultClient client = new VaultClient(
                VaultJwtConfig.builder().vaultUrl(wm.getHttpBaseUrl()).build());
        assertDoesNotThrow(() -> client.revokeSelf("tok"));
        wm.getWireMock()
                .verifyThat(postRequestedFor(urlEqualTo("/v1/auth/token/revoke-self"))
                        .withHeader("X-Vault-Token", equalTo("tok")));
    }

    @Test
    void healthCheckAcceptsStandbyCodes(WireMockRuntimeInfo wm) throws Exception {
        wm.getWireMock()
                .register(get(urlEqualTo("/v1/sys/health"))
                        .willReturn(aResponse().withStatus(429).withBody("{}")));
        VaultClient client = new VaultClient(
                VaultJwtConfig.builder().vaultUrl(wm.getHttpBaseUrl()).build());
        assertDoesNotThrow(client::healthCheck);
    }
}
