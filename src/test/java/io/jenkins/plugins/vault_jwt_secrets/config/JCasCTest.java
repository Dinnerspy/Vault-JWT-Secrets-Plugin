package io.jenkins.plugins.vault_jwt_secrets.config;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import org.junit.Rule;
import org.junit.Test;

public class JCasCTest {

    @Rule
    public JenkinsConfiguredWithCodeRule r = new JenkinsConfiguredWithCodeRule();

    @Test
    @ConfiguredWithCode("configuration-as-code.yaml")
    public void globalConfigurationIsLoadedFromYaml() {
        VaultJwtGlobalConfiguration global = VaultJwtGlobalConfiguration.get();
        assertEquals("https://vault.example.com", global.getVaultUrl());
        assertEquals("jwt-jenkins", global.getAuthPath());
        assertEquals("jenkins-default", global.getRole());
        assertEquals("team-a", global.getNamespace());
        assertEquals("kv", global.getDefaultMount());
        assertTrue(!global.isSkipTlsVerify());
    }
}
