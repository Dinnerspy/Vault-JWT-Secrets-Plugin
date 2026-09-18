package io.jenkins.plugins.vault_jwt_secrets.steps;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import io.jenkins.plugins.vault_jwt_secrets.JwtTestUtil;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultJwtGlobalConfiguration;
import java.util.List;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
@WireMockTest
class WithVaultJwtSecretsStepTest {

    private static final String SECRET_VALUE = "hunter2-sup3r-s3cret";

    private static void stubVault(WireMockRuntimeInfo wm) {
        wm.getWireMock()
                .register(post(urlEqualTo("/v1/auth/jwt/login"))
                        .willReturn(
                                aResponse().withStatus(200).withBody("{\"auth\":{\"client_token\":\"vault-tok\"}}")));
        wm.getWireMock()
                .register(get(urlEqualTo("/v1/ops/data/production/db"))
                        .willReturn(aResponse()
                                .withStatus(200)
                                .withBody("{\"data\":{\"data\":{\"password\":\"" + SECRET_VALUE
                                        + "\",\"username\":\"app\"}}}")));
        wm.getWireMock()
                .register(post(urlEqualTo("/v1/auth/token/revoke-self"))
                        .willReturn(aResponse().withStatus(204)));
    }

    private static void configureGlobal(WireMockRuntimeInfo wm) {
        VaultJwtGlobalConfiguration global = VaultJwtGlobalConfiguration.get();
        global.setVaultUrl(wm.getHttpBaseUrl());
        global.setRole("demo");
    }

    @Test
    void fetchesEnvSecretMasksItAndScopesItToTheBlock(JenkinsRule r, WireMockRuntimeInfo wm) throws Exception {
        stubVault(wm);
        configureGlobal(wm);
        WorkflowJob job = r.createProject(WorkflowJob.class, "envjob");
        job.setDefinition(new CpsFlowDefinition(
                "node {\n"
                        + "  withVaultJwtSecrets(secrets: [vaultSecret(path: 'production/db@ops', field: 'password', var: 'DB_PASSWORD')]) {\n"
                        + "    sh 'echo password is $DB_PASSWORD'\n"
                        + "  }\n"
                        + "  sh 'echo after=[$DB_PASSWORD]'\n"
                        + "}",
                true));
        WorkflowRun build = r.buildAndAssertSuccess(job);
        r.assertLogNotContains(SECRET_VALUE, build);
        r.assertLogContains("password is ****", build);
        r.assertLogContains("after=[]", build);
        r.assertLogContains("Fetched 1 secret(s)", build);

        // the login JWT must be a per-build token minted by oidc-provider
        List<LoggedRequest> logins = wm.getWireMock()
                .find(com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor(
                        urlEqualTo("/v1/auth/jwt/login")));
        assertEquals(1, logins.size());
        JsonNode loginBody = new ObjectMapper().readTree(logins.get(0).getBodyAsString());
        assertEquals("demo", loginBody.path("role").asText());
        String jwt = loginBody.path("jwt").asText();
        JsonNode payload = JwtTestUtil.payload(jwt);
        assertEquals(r.getURL() + "job/envjob/", payload.path("sub").asText());
        assertEquals(wm.getHttpBaseUrl(), JwtTestUtil.audience(jwt));
        assertEquals(r.getURL() + "oidc", payload.path("iss").asText());
    }

    @Test
    void fileSecretIsWrittenScopedAndCleanedUp(JenkinsRule r, WireMockRuntimeInfo wm) throws Exception {
        stubVault(wm);
        configureGlobal(wm);
        WorkflowJob job = r.createProject(WorkflowJob.class, "filejob");
        job.setDefinition(new CpsFlowDefinition(
                "node {\n"
                        + "  def path\n"
                        + "  withVaultJwtSecrets(secrets: [vaultSecret(path: 'production/db@ops', field: 'password', var: 'SECRET_FILE', type: 'file')]) {\n"
                        + "    path = env.SECRET_FILE\n"
                        + "    def content = readFile(env.SECRET_FILE)\n"
                        + "    if (content != '" + SECRET_VALUE + "') { error('content mismatch') }\n"
                        + "  }\n"
                        + "  if (fileExists(path)) { error('temp file still exists after block') }\n"
                        + "}",
                true));
        WorkflowRun build = r.buildAndAssertSuccess(job);
        r.assertLogNotContains(SECRET_VALUE, build);
    }

    @Test
    void missingFieldFailsListingAvailableFieldNames(JenkinsRule r, WireMockRuntimeInfo wm) throws Exception {
        stubVault(wm);
        configureGlobal(wm);
        WorkflowJob job = r.createProject(WorkflowJob.class, "missingfield");
        job.setDefinition(new CpsFlowDefinition(
                "node {\n"
                        + "  withVaultJwtSecrets(secrets: [vaultSecret(path: 'production/db@ops', field: 'nope', var: 'X')]) {\n"
                        + "    echo 'unreachable'\n"
                        + "  }\n"
                        + "}",
                true));
        WorkflowRun build = r.buildAndAssertStatus(hudson.model.Result.FAILURE, job);
        r.assertLogContains("field 'nope' not found", build);
        r.assertLogContains("Available fields: password, username", build);
        r.assertLogNotContains(SECRET_VALUE, build);
    }

    @Test
    void vaultLoginRejectionFailsWithVaultError(JenkinsRule r, WireMockRuntimeInfo wm) throws Exception {
        wm.getWireMock()
                .register(
                        post(urlEqualTo("/v1/auth/jwt/login"))
                                .willReturn(
                                        aResponse()
                                                .withStatus(403)
                                                .withBody(
                                                        "{\"errors\":[\"error validating claims: claim \\\"sub\\\" does not match\"]}")));
        configureGlobal(wm);
        WorkflowJob job = r.createProject(WorkflowJob.class, "rejected");
        job.setDefinition(new CpsFlowDefinition(
                "node {\n"
                        + "  withVaultJwtSecrets(secrets: [vaultSecret(path: 'production/db@ops', field: 'password', var: 'X')]) {\n"
                        + "    echo 'unreachable'\n"
                        + "  }\n"
                        + "}",
                true));
        WorkflowRun build = r.buildAndAssertStatus(hudson.model.Result.FAILURE, job);
        r.assertLogContains("does not match", build);
        r.assertLogContains("bound_audiences", build);
    }

    @Test
    void stepParametersOverrideGlobalConfig(JenkinsRule r, WireMockRuntimeInfo wm) throws Exception {
        stubVault(wm);
        VaultJwtGlobalConfiguration global = VaultJwtGlobalConfiguration.get();
        global.setVaultUrl("https://unreachable.invalid");
        global.setRole("wrong-role");
        WorkflowJob job = r.createProject(WorkflowJob.class, "overrides");
        job.setDefinition(new CpsFlowDefinition(
                "node {\n"
                        + "  withVaultJwtSecrets(vaultUrl: '" + wm.getHttpBaseUrl() + "', role: 'demo',\n"
                        + "      secrets: [vaultSecret(path: 'production/db@ops', field: 'password', var: 'PW')]) {\n"
                        + "    sh 'echo got $PW'\n"
                        + "  }\n"
                        + "}",
                true));
        WorkflowRun build = r.buildAndAssertSuccess(job);
        r.assertLogContains("got ****", build);
    }

    @Test
    void gitlabOneLinePathInfersTheField(JenkinsRule r, WireMockRuntimeInfo wm) throws Exception {
        stubVault(wm);
        configureGlobal(wm);
        WorkflowJob job = r.createProject(WorkflowJob.class, "shorthand");
        job.setDefinition(new CpsFlowDefinition(
                "node {\n"
                        + "  withVaultJwtSecrets(secrets: [vaultSecret(path: 'production/db/password@ops', var: 'PW')]) {\n"
                        + "    sh 'echo got $PW'\n"
                        + "  }\n"
                        + "}",
                true));
        WorkflowRun build = r.buildAndAssertSuccess(job);
        r.assertLogContains("got ****", build);
        r.assertLogNotContains(SECRET_VALUE, build);
    }

    @Test
    void gitlabVaultEnvironmentVariablesConfigureTheStep(JenkinsRule r, WireMockRuntimeInfo wm) throws Exception {
        stubVault(wm);
        // nothing configured globally or on a folder: the GitLab variable names carry the whole config
        WorkflowJob job = r.createProject(WorkflowJob.class, "envconfig");
        job.setDefinition(new CpsFlowDefinition(
                "node {\n"
                        + "  withEnv(['VAULT_SERVER_URL=" + wm.getHttpBaseUrl() + "', 'VAULT_AUTH_ROLE=demo']) {\n"
                        + "    withVaultJwtSecrets(secrets: [vaultSecret(path: 'production/db/password@ops', var: 'PW')]) {\n"
                        + "      sh 'echo got $PW'\n"
                        + "    }\n"
                        + "  }\n"
                        + "}",
                true));
        WorkflowRun build = r.buildAndAssertSuccess(job);
        r.assertLogContains("got ****", build);

        List<LoggedRequest> logins = wm.getWireMock()
                .find(com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor(
                        urlEqualTo("/v1/auth/jwt/login")));
        assertEquals(1, logins.size());
        assertEquals(
                "demo",
                new ObjectMapper()
                        .readTree(logins.get(0).getBodyAsString())
                        .path("role")
                        .asText());
    }

    @Test
    void stepParameterBeatsTheGitlabEnvironmentVariable(JenkinsRule r, WireMockRuntimeInfo wm) throws Exception {
        stubVault(wm);
        WorkflowJob job = r.createProject(WorkflowJob.class, "envprecedence");
        job.setDefinition(new CpsFlowDefinition(
                "node {\n"
                        + "  withEnv(['VAULT_SERVER_URL=" + wm.getHttpBaseUrl() + "', 'VAULT_AUTH_ROLE=from-env']) {\n"
                        + "    withVaultJwtSecrets(role: 'from-step',\n"
                        + "        secrets: [vaultSecret(path: 'production/db@ops', field: 'password', var: 'PW')]) {\n"
                        + "      sh 'echo got $PW'\n"
                        + "    }\n"
                        + "  }\n"
                        + "}",
                true));
        r.buildAndAssertSuccess(job);
        List<LoggedRequest> logins = wm.getWireMock()
                .find(com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor(
                        urlEqualTo("/v1/auth/jwt/login")));
        assertEquals(
                "from-step",
                new ObjectMapper()
                        .readTree(logins.get(0).getBodyAsString())
                        .path("role")
                        .asText());
    }

    @Test
    void declarativeOptionsBlockWorks(JenkinsRule r, WireMockRuntimeInfo wm) throws Exception {
        stubVault(wm);
        configureGlobal(wm);
        WorkflowJob job = r.createProject(WorkflowJob.class, "declarative");
        job.setDefinition(new CpsFlowDefinition(
                "pipeline {\n"
                        + "  agent any\n"
                        + "  options {\n"
                        + "    withVaultJwtSecrets(secrets: [vaultSecret(path: 'production/db@ops', field: 'password', var: 'DB_PASSWORD')])\n"
                        + "  }\n"
                        + "  stages {\n"
                        + "    stage('use') {\n"
                        + "      steps { sh 'echo password is $DB_PASSWORD' }\n"
                        + "    }\n"
                        + "  }\n"
                        + "}",
                true));
        WorkflowRun build = r.buildAndAssertSuccess(job);
        r.assertLogNotContains(SECRET_VALUE, build);
        r.assertLogContains("password is ****", build);
    }
}
