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

/**
 * Merges Vault settings global configuration → outermost..innermost folder properties → overrides
 * supplied by a step or credential. Inner layers win.
 */
public final class VaultConfigResolver {

    private VaultConfigResolver() {}

    @NonNull
    public static VaultJwtConfig resolve(@NonNull Run<?, ?> run, @CheckForNull VaultJwtConfig overrides)
            throws AbortException {
        return resolve(run.getParent(), overrides);
    }

    @NonNull
    public static VaultJwtConfig resolve(@NonNull Item item, @CheckForNull VaultJwtConfig overrides)
            throws AbortException {
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
        config = config.mergedWith(overrides);
        return validated(config);
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
