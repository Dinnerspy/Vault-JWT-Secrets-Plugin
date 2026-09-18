package io.jenkins.plugins.vault_jwt_secrets.config;

import com.cloudbees.hudson.plugins.folder.AbstractFolder;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.AbortException;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.Run;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;

/**
 * Merges Vault settings global configuration → outermost..innermost folder properties →
 * {@code VAULT_*} build environment variables → overrides supplied by a step or credential.
 * Inner layers win.
 */
public final class VaultConfigResolver {

    /** GitLab CI's Vault variables, honoured here so the same names configure both systems. */
    public static final String ENV_SERVER_URL = "VAULT_SERVER_URL";

    public static final String ENV_AUTH_ROLE = "VAULT_AUTH_ROLE";
    public static final String ENV_AUTH_PATH = "VAULT_AUTH_PATH";
    public static final String ENV_NAMESPACE = "VAULT_NAMESPACE";

    private VaultConfigResolver() {}

    @NonNull
    public static VaultJwtConfig resolve(@NonNull Run<?, ?> run, @CheckForNull VaultJwtConfig overrides)
            throws AbortException {
        return resolve(run.getParent(), overrides, null);
    }

    /** As {@link #resolve(Run, VaultJwtConfig)}, expanding {@code ${VAR}} references against {@code env}. */
    @NonNull
    public static VaultJwtConfig resolve(
            @NonNull Run<?, ?> run, @CheckForNull VaultJwtConfig overrides, @CheckForNull Map<String, String> env)
            throws AbortException {
        return resolve(run.getParent(), overrides, env);
    }

    @NonNull
    public static VaultJwtConfig resolve(@NonNull Item item, @CheckForNull VaultJwtConfig overrides)
            throws AbortException {
        return resolve(item, overrides, null);
    }

    @NonNull
    public static VaultJwtConfig resolve(
            @NonNull Item item, @CheckForNull VaultJwtConfig overrides, @CheckForNull Map<String, String> env)
            throws AbortException {
        return validated(merged(item, overrides, env));
    }

    /**
     * Merges the same layers as {@link #resolve(Item, VaultJwtConfig, Map)} but skips the
     * {@code vaultUrl}/{@code role} requirement — for callers that only need the id token audience.
     */
    @NonNull
    public static VaultJwtConfig resolveForToken(
            @NonNull Run<?, ?> run, @CheckForNull VaultJwtConfig overrides, @CheckForNull Map<String, String> env) {
        return merged(run.getParent(), overrides, env);
    }

    private static VaultJwtConfig merged(
            @NonNull Item item, @CheckForNull VaultJwtConfig overrides, @CheckForNull Map<String, String> env) {
        VaultJwtConfig config = VaultJwtGlobalConfiguration.get().toConfig();
        Deque<VaultJwtConfig> folderLayers = new ArrayDeque<>();
        ItemGroup<?> parent = item.getParent();
        while (parent instanceof AbstractFolder) {
            AbstractFolder<?> folder = (AbstractFolder<?>) parent;
            VaultJwtFolderProperty property = folder.getProperties().get(VaultJwtFolderProperty.class);
            if (property != null) {
                folderLayers.addFirst(property.toConfig());
            }
            parent = folder.getParent();
        }
        for (VaultJwtConfig layer : folderLayers) {
            config = config.mergedWith(layer);
        }
        config = config.mergedWith(fromEnvironment(env));
        config = config.mergedWith(overrides);
        return config.expandedWith(env);
    }

    /**
     * GitLab configures Vault entirely through CI/CD variables; the same variable names work here, so a
     * job can set {@code environment { VAULT_SERVER_URL = ...; VAULT_AUTH_ROLE = ... }} and call the step
     * with nothing but its list of secrets. They sit between folder properties and explicit step
     * parameters: a job-level variable overrides its folder, an argument passed to the step overrides both.
     */
    @CheckForNull
    private static VaultJwtConfig fromEnvironment(@CheckForNull Map<String, String> env) {
        if (env == null || env.isEmpty()) {
            return null;
        }
        return VaultJwtConfig.builder()
                .vaultUrl(env.get(ENV_SERVER_URL))
                .role(env.get(ENV_AUTH_ROLE))
                .authPath(env.get(ENV_AUTH_PATH))
                .namespace(env.get(ENV_NAMESPACE))
                .build();
    }

    /** Resolution outside any job context (e.g. connectivity test from the global form). */
    @NonNull
    public static VaultJwtConfig resolveGlobal(@CheckForNull VaultJwtConfig overrides) throws AbortException {
        return validated(VaultJwtGlobalConfiguration.get().toConfig().mergedWith(overrides));
    }

    private static VaultJwtConfig validated(VaultJwtConfig config) throws AbortException {
        String vaultUrl = config.getVaultUrl();
        if (vaultUrl == null || vaultUrl.isBlank()) {
            throw new AbortException("No Vault URL configured. Set one in Manage Jenkins » System"
                    + " » Vault JWT Secrets, on a parent folder, or as a step parameter (vaultUrl:).");
        }
        String role = config.getRole();
        if (role == null || role.isBlank()) {
            throw new AbortException("No Vault role configured. Set a default role in the global or folder"
                    + " configuration, or pass role: to the step / credential.");
        }
        return config;
    }
}
