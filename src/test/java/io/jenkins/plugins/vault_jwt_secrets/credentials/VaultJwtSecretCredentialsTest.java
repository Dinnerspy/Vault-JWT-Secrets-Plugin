package io.jenkins.plugins.vault_jwt_secrets.credentials;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultJwtGlobalConfiguration;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
@WireMockTest
class VaultJwtSecretCredentialsTest {

    private static final String SECRET_VALUE = "db-pass-31337";

    @Test
    void resolvesPerBuildViaWithCredentialsAndIsMasked(JenkinsRule r, WireMockRuntimeInfo wm) throws Exception {
        wm.getWireMock()
                .register(post(urlEqualTo("/v1/auth/jwt/login"))
                        .willReturn(
                                aResponse().withStatus(200).withBody("{\"auth\":{\"client_token\":\"vault-tok\"}}")));
        wm.getWireMock()
                .register(get(urlEqualTo("/v1/ops/data/production/db"))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withBody("{\"data\":{\"data\":{\"password\":\"" + SECRET_VALUE + "\"}}}")));
        wm.getWireMock()
                .register(post(urlEqualTo("/v1/auth/token/revoke-self"))
                        .willReturn(aResponse().withStatus(204)));

        VaultJwtGlobalConfiguration global = VaultJwtGlobalConfiguration.get();
        global.setVaultUrl(wm.getHttpBaseUrl());
        global.setRole("demo");

        VaultJwtSecretCredentials credentials = new VaultJwtSecretCredentials(
                CredentialsScope.GLOBAL, "prod-db-password", "prod db", "production/db@ops", "password");
        SystemCredentialsProvider.getInstance().getCredentials().add(credentials);
        SystemCredentialsProvider.getInstance().save();

        WorkflowJob job = r.createProject(WorkflowJob.class, "creduser");
        job.setDefinition(new CpsFlowDefinition(
                "node {\n"
                        + "  withCredentials([string(credentialsId: 'prod-db-password', variable: 'PW')]) {\n"
                        + "    sh 'echo password is $PW'\n"
                        + "  }\n"
                        + "}",
                true));
        WorkflowRun build = r.buildAndAssertSuccess(job);
        r.assertLogNotContains(SECRET_VALUE, build);
        r.assertLogContains("password is ****", build);
    }
}
