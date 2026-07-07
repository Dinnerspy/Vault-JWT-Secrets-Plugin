package io.jenkins.plugins.vault_jwt_secrets.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.cloudbees.hudson.plugins.folder.Folder;
import hudson.AbortException;
import hudson.model.FreeStyleProject;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class VaultConfigResolverTest {

    @Test
    void innerLayersWin(JenkinsRule r) throws Exception {
        VaultJwtGlobalConfiguration global = VaultJwtGlobalConfiguration.get();
        global.setVaultUrl("https://global.vault.example.com");
        global.setRole("global-role");
        global.setNamespace("global-ns");

        Folder outer = r.jenkins.createProject(Folder.class, "outer");
        VaultJwtFolderProperty outerProperty = new VaultJwtFolderProperty();
        outerProperty.setRole("outer-role");
        outerProperty.setDefaultMount("outer-mount");
        outer.addProperty(outerProperty);

        Folder inner = outer.createProject(Folder.class, "inner");
        VaultJwtFolderProperty innerProperty = new VaultJwtFolderProperty();
        innerProperty.setRole("inner-role");
        inner.addProperty(innerProperty);

        FreeStyleProject job = inner.createProject(FreeStyleProject.class, "job");

        VaultJwtConfig resolved = VaultConfigResolver.resolve(job, null);
        assertEquals("https://global.vault.example.com", resolved.getVaultUrl());
        assertEquals("global-ns", resolved.getNamespace());
        assertEquals("inner-role", resolved.getRole());
        assertEquals("outer-mount", resolved.getEffectiveDefaultMount());
        assertEquals("jwt", resolved.getEffectiveAuthPath());
        assertEquals("https://global.vault.example.com", resolved.getEffectiveAudience());

        VaultJwtConfig withStepOverrides = VaultConfigResolver.resolve(
                job, VaultJwtConfig.builder().role("step-role").build());
        assertEquals("step-role", withStepOverrides.getRole());
    }

    @Test
    void missingVaultUrlOrRoleAborts(JenkinsRule r) throws Exception {
        FreeStyleProject job = r.createFreeStyleProject();
        assertThrows(AbortException.class, () -> VaultConfigResolver.resolve(job, null));
        VaultJwtGlobalConfiguration.get().setVaultUrl("https://v.example.com");
        assertThrows(AbortException.class, () -> VaultConfigResolver.resolve(job, null));
        VaultJwtConfig config = VaultConfigResolver.resolve(
                job, VaultJwtConfig.builder().role("step-role").build());
        assertEquals("step-role", config.getRole());
    }
}
