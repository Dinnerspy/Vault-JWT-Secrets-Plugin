package io.jenkins.plugins.vault_jwt_secrets.steps;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.jenkins.plugins.vault_jwt_secrets.JwtTestUtil;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultJwtGlobalConfiguration;
import java.util.Objects;
import org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition;
import org.jenkinsci.plugins.workflow.job.WorkflowJob;
import org.jenkinsci.plugins.workflow.job.WorkflowRun;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class WithVaultJwtTokenStepTest {

    /** The token is written to a workspace file so the test can inspect it without it appearing in the log. */
    private static String tokenFrom(JenkinsRule r, WorkflowJob job) throws Exception {
        return Objects.requireNonNull(r.jenkins.getWorkspaceFor(job))
                .child("tok.txt")
                .readToString();
    }

    @Test
    void exposesMaskedTokenScopedToTheBlock(JenkinsRule r) throws Exception {
        VaultJwtGlobalConfiguration.get().setVaultUrl("https://vault.example.test");
        WorkflowJob job = r.createProject(WorkflowJob.class, "tokenjob");
        job.setDefinition(new CpsFlowDefinition(
                "node {\n"
                        + "  withVaultJwtToken {\n"
                        + "    writeFile file: 'tok.txt', text: env.VAULT_ID_TOKEN\n"
                        + "    sh 'echo token is $VAULT_ID_TOKEN'\n"
                        + "  }\n"
                        + "  sh 'echo after=[$VAULT_ID_TOKEN]'\n"
                        + "}",
                true));
        WorkflowRun build = r.buildAndAssertSuccess(job);
        r.assertLogContains("token is ****", build);
        r.assertLogContains("after=[]", build);

        String jwt = tokenFrom(r, job);
        r.assertLogNotContains(jwt, build);
        assertEquals("https://vault.example.test", JwtTestUtil.audience(jwt));
        assertEquals(
                r.getURL() + "job/tokenjob/",
                JwtTestUtil.payload(jwt).path("sub").asText());
        assertEquals(r.getURL() + "oidc", JwtTestUtil.payload(jwt).path("iss").asText());
    }

    @Test
    void audienceIsExpandedFromTheBuildEnvironment(JenkinsRule r) throws Exception {
        VaultJwtGlobalConfiguration.get().setVaultUrl("https://ignored.example.test");
        WorkflowJob job = r.createProject(WorkflowJob.class, "envaud");
        job.setDefinition(new CpsFlowDefinition(
                "node {\n"
                        + "  withEnv(['MY_VAULT=https://vault.team-a.test']) {\n"
                        + "    withVaultJwtToken(audience: '${MY_VAULT}', variable: 'JWT') {\n"
                        + "      writeFile file: 'tok.txt', text: env.JWT\n"
                        + "    }\n"
                        + "  }\n"
                        + "}",
                true));
        r.buildAndAssertSuccess(job);
        assertEquals("https://vault.team-a.test", JwtTestUtil.audience(tokenFrom(r, job)));
    }

    @Test
    void carriesTheJobIdentityClaims(JenkinsRule r) throws Exception {
        VaultJwtGlobalConfiguration.get().setVaultUrl("https://vault.example.test");
        WorkflowJob job = r.createProject(WorkflowJob.class, "claims");
        job.setDefinition(new CpsFlowDefinition(
                "node { withVaultJwtToken { writeFile file: 'tok.txt', text: env.VAULT_ID_TOKEN } }", true));
        r.buildAndAssertSuccess(job);
        assertEquals(
                "claims",
                JwtTestUtil.payload(tokenFrom(r, job)).path("job_path").asText());
    }

    @Test
    void failsWhenNoAudienceCanBeResolved(JenkinsRule r) throws Exception {
        WorkflowJob job = r.createProject(WorkflowJob.class, "noaud");
        job.setDefinition(new CpsFlowDefinition("node { withVaultJwtToken { echo 'unreachable' } }", true));
        WorkflowRun build = r.buildAndAssertStatus(hudson.model.Result.FAILURE, job);
        r.assertLogContains("no audience", build);
    }

    @Test
    void rejectsAnInvalidVariableName(JenkinsRule r) throws Exception {
        VaultJwtGlobalConfiguration.get().setVaultUrl("https://vault.example.test");
        WorkflowJob job = r.createProject(WorkflowJob.class, "badvar");
        job.setDefinition(new CpsFlowDefinition(
                "node { withVaultJwtToken(variable: 'not a var') { echo 'unreachable' } }", true));
        WorkflowRun build = r.buildAndAssertStatus(hudson.model.Result.FAILURE, job);
        r.assertLogContains("is not a valid environment variable name", build);
    }
}
