package io.jenkins.plugins.vault_jwt_secrets.config;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import com.cloudbees.hudson.plugins.folder.AbstractFolderProperty;
import com.cloudbees.hudson.plugins.folder.AbstractFolderPropertyDescriptor;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/** Folder-level overrides of the global Vault JWT settings; nested folders override their parents. */
public class VaultJwtFolderProperty extends AbstractFolderProperty<AbstractFolder<?>> {

    private String vaultUrl;
    private String authPath;
    private String role;
    private String namespace;
    private String defaultMount;
    private String audience;

    @DataBoundConstructor
    public VaultJwtFolderProperty() {}

    @NonNull
    public VaultJwtConfig toConfig() {
        return VaultJwtConfig.builder()
                .vaultUrl(vaultUrl)
                .authPath(authPath)
                .role(role)
                .namespace(namespace)
                .defaultMount(defaultMount)
                .audience(audience)
                .build();
    }

    @CheckForNull
    public String getVaultUrl() {
        return vaultUrl;
    }

    @DataBoundSetter
    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = trimToNull(vaultUrl);
    }

    @CheckForNull
    public String getAuthPath() {
        return authPath;
    }

    @DataBoundSetter
    public void setAuthPath(String authPath) {
        this.authPath = trimToNull(authPath);
    }

    @CheckForNull
    public String getRole() {
        return role;
    }

    @DataBoundSetter
    public void setRole(String role) {
        this.role = trimToNull(role);
    }

    @CheckForNull
    public String getNamespace() {
        return namespace;
    }

    @DataBoundSetter
    public void setNamespace(String namespace) {
        this.namespace = trimToNull(namespace);
    }

    @CheckForNull
    public String getDefaultMount() {
        return defaultMount;
    }

    @DataBoundSetter
    public void setDefaultMount(String defaultMount) {
        this.defaultMount = trimToNull(defaultMount);
    }

    @CheckForNull
    public String getAudience() {
        return audience;
    }

    @DataBoundSetter
    public void setAudience(String audience) {
        this.audience = trimToNull(audience);
    }

    @CheckForNull
    private static String trimToNull(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    @Symbol("vaultJwtSecrets")
    @Extension
    public static class DescriptorImpl extends AbstractFolderPropertyDescriptor {
        @NonNull
        @Override
        public String getDisplayName() {
            return "Vault JWT Secrets overrides";
        }
    }
}
