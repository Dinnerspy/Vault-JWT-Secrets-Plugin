package io.jenkins.plugins.vault_jwt_secrets.idtoken;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.cloudbees.hudson.plugins.folder.Folder;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import io.jenkins.plugins.oidc_provider.IdTokenStringCredentials;
import io.jenkins.plugins.vault_jwt_secrets.JwtTestUtil;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultJwtConfig;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class IdTokenSupplierTest {

    private static final String AUDIENCE = "https://vault.example.com";

    @Test
    void provisioningIsIdempotent(JenkinsRule r) throws Exception {
        String id1 = IdTokenSupplier.getOrCreateIdTokenCredentials(AUDIENCE);
        String id2 = IdTokenSupplier.getOrCreateIdTokenCredentials(AUDIENCE);
        assertEquals(id1, id2);
        assertTrue(id1.startsWith(IdTokenSupplier.CREDENTIALS_ID_PREFIX));
        long count = SystemCredentialsProvider.getInstance().getCredentials().stream()
                .filter(IdTokenStringCredentials.class::isInstance)
                .count();
        assertEquals(1, count);
        String other = IdTokenSupplier.getOrCreateIdTokenCredentials("https://other.example.com");
        assertTrue(!other.equals(id1));
    }

    @Test
    void provisionedKeyIsServedByRootJwks(JenkinsRule r) throws Exception {
        String id = IdTokenSupplier.getOrCreateIdTokenCredentials(AUDIENCE);
        String jwks = r.createWebClient()
                .goTo("oidc/jwks", "application/json")
                .getWebResponse()
                .getContentAsString();
        JsonNode keys = new ObjectMapper().readTree(jwks).path("keys");
        assertTrue(keys.isArray() && keys.size() >= 1, jwks);
        boolean found = false;
        for (JsonNode key : keys) {
            if (id.equals(key.path("kid").asText())) {
                found = true;
            }
        }
        assertTrue(found, "kid " + id + " not present in " + jwks);
    }

    @Test
    void mintForBuildCarriesBuildClaims(JenkinsRule r) throws Exception {
        FreeStyleProject project = r.createFreeStyleProject("myjob");
        FreeStyleBuild build = r.buildAndAssertSuccess(project);
        VaultJwtConfig config = VaultJwtConfig.builder().vaultUrl(AUDIENCE).build();
        String jwt = IdTokenSupplier.mintForBuild(build, config);
        JsonNode payload = JwtTestUtil.payload(jwt);
        assertEquals(r.getURL() + "job/myjob/", payload.path("sub").asText());
        assertEquals(AUDIENCE, JwtTestUtil.audience(jwt));
        assertEquals(r.getURL() + "oidc", payload.path("iss").asText());
        assertEquals(1, payload.path("build_number").asInt());
        // usage of the credential should be recorded on the build
        assertTrue(jwt.split("\\.").length == 3);
    }

    @Test
    void mintForBuildCarriesJobAndFolderPathClaims(JenkinsRule r) throws Exception {
        Folder team = r.jenkins.createProject(Folder.class, "team-a");
        Folder backend = team.createProject(Folder.class, "backend");
        FreeStyleProject project = backend.createProject(FreeStyleProject.class, "deploy");
        FreeStyleBuild build = r.buildAndAssertSuccess(project);

        VaultJwtConfig config = VaultJwtConfig.builder().vaultUrl(AUDIENCE).build();
        JsonNode payload = JwtTestUtil.payload(IdTokenSupplier.mintForBuild(build, config));

        assertEquals("team-a/backend/deploy", payload.path("job_path").asText());
        assertEquals("team-a/backend", payload.path("folder_path").asText());
        assertEquals("deploy", payload.path("job_name").asText());
        assertEquals(
                r.getURL() + "job/team-a/job/backend/job/deploy/",
                payload.path("job_url").asText());
    }

    @Test
    void folderPathIsEmptyForTopLevelJob(JenkinsRule r) throws Exception {
        FreeStyleProject project = r.createFreeStyleProject("toplevel");
        FreeStyleBuild build = r.buildAndAssertSuccess(project);
        VaultJwtConfig config = VaultJwtConfig.builder().vaultUrl(AUDIENCE).build();
        JsonNode payload = JwtTestUtil.payload(IdTokenSupplier.mintForBuild(build, config));
        assertEquals("toplevel", payload.path("job_path").asText());
        assertEquals("", payload.path("folder_path").asText());
    }

    @Test
    void explicitCredentialsIdBypassesProvisioning(JenkinsRule r) throws Exception {
        IdTokenStringCredentials manual = new IdTokenStringCredentials(
                com.cloudbees.plugins.credentials.CredentialsScope.GLOBAL, "manual-token", null);
        manual.setAudience(AUDIENCE);
        SystemCredentialsProvider.getInstance().getCredentials().add(manual);
        SystemCredentialsProvider.getInstance().save();

        FreeStyleProject project = r.createFreeStyleProject();
        FreeStyleBuild build = r.buildAndAssertSuccess(project);
        VaultJwtConfig config = VaultJwtConfig.builder()
                .vaultUrl(AUDIENCE)
                .idTokenCredentialsId("manual-token")
                .build();
        String jwt = IdTokenSupplier.mintForBuild(build, config);
        assertEquals("manual-token", JwtTestUtil.header(jwt).path("kid").asText());
        long provisioned = SystemCredentialsProvider.getInstance().getCredentials().stream()
                .filter(c -> c instanceof IdTokenStringCredentials
                        && ((IdTokenStringCredentials) c).getId().startsWith(IdTokenSupplier.CREDENTIALS_ID_PREFIX))
                .count();
        assertEquals(0, provisioned);
    }
}
