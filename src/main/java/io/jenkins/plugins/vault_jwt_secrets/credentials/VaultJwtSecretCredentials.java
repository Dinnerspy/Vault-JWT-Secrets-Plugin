package io.jenkins.plugins.vault_jwt_secrets.credentials;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.impl.BaseStandardCredentials;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.util.Secret;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultConfigResolver;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultJwtConfig;
import io.jenkins.plugins.vault_jwt_secrets.idtoken.IdTokenSupplier;
import io.jenkins.plugins.vault_jwt_secrets.vault.KvV2Ref;
import io.jenkins.plugins.vault_jwt_secrets.vault.VaultClient;
import java.util.Map;
import java.util.Objects;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

/**
 * A credential whose value lives in Vault, not in Jenkins. Each time it is used in a build
 * (e.g. via {@code withCredentials}) it logs into Vault with a fresh per-build JWT and reads
 * the configured KV v2 field. Consumable anywhere a secret-text credential is accepted.
 */
public class VaultJwtSecretCredentials extends BaseStandardCredentials implements StringCredentials {

    private static final long serialVersionUID = 1L;

    private final String path;
    private final String field;
    private String role;
    private String vaultUrl;
    private String authPath;
    private String namespace;
    private String audience;

    private transient @CheckForNull Run<?, ?> build;

    @DataBoundConstructor
    public VaultJwtSecretCredentials(
            @CheckForNull CredentialsScope scope,
            @CheckForNull String id,
            @CheckForNull String description,
            @NonNull String path,
            @CheckForNull String field) {
        super(scope, id, description);
        this.path = path.trim();
        this.field = field == null || field.isBlank() ? null : field.trim();
    }

    public String getPath() {
        return path;
    }

    @CheckForNull
    public String getField() {
        return field;
    }

    /** The secret path with the field stripped off (GitLab's one-line form when no field is set). */
    @NonNull
    public String effectivePath() {
        return field != null ? path : KvV2Ref.splitTrailingField(path)[0];
    }

    /** The field to read: the explicit one, else the last segment of {@code path}. */
    @NonNull
    public String effectiveField() {
        return field != null ? field : KvV2Ref.splitTrailingField(path)[1];
    }

    @CheckForNull
    public String getRole() {
        return role;
    }

    @DataBoundSetter
    public void setRole(String role) {
        this.role = role;
    }

    @CheckForNull
    public String getVaultUrl() {
        return vaultUrl;
    }

    @DataBoundSetter
    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = vaultUrl;
    }

    @CheckForNull
    public String getAuthPath() {
        return authPath;
    }

    @DataBoundSetter
    public void setAuthPath(String authPath) {
        this.authPath = authPath;
    }

    @CheckForNull
    public String getNamespace() {
        return namespace;
    }

    @DataBoundSetter
    public void setNamespace(String namespace) {
        this.namespace = namespace;
    }

    @CheckForNull
    public String getAudience() {
        return audience;
    }

    @DataBoundSetter
    public void setAudience(String audience) {
        this.audience = audience;
    }

    @Override
    public Credentials forRun(Run<?, ?> context) {
        VaultJwtSecretCredentials clone =
                new VaultJwtSecretCredentials(getScope(), getId(), getDescription(), path, field);
        clone.role = role;
        clone.vaultUrl = vaultUrl;
        clone.authPath = authPath;
        clone.namespace = namespace;
        clone.audience = audience;
        clone.build = context;
        return clone;
    }

    @NonNull
    @Override
    public Secret getSecret() {
        try {
            VaultJwtConfig overrides = VaultJwtConfig.builder()
                    .vaultUrl(vaultUrl)
                    .authPath(authPath)
                    .role(role)
                    .namespace(namespace)
                    .audience(audience)
                    .build();
            VaultJwtConfig config;
            String jwt;
            if (build != null) {
                // ${VAR} references in the connection settings resolve against the build environment
                config = VaultConfigResolver.resolve(build, overrides, build.getEnvironment(TaskListener.NULL));
                jwt = IdTokenSupplier.mintForBuild(build, config);
            } else {
                // outside a build (e.g. form validation): non-build claims, global+override config only
                config = VaultConfigResolver.resolveGlobal(overrides);
                // resolveGlobal validated vaultUrl, so the audience (which falls back to it) is non-null
                IdTokenSupplier.getOrCreateIdTokenCredentials(Objects.requireNonNull(config.getEffectiveAudience()));
                jwt = IdTokenSupplier.mintGlobal(config);
            }
            VaultClient client = new VaultClient(config);
            // config is validated: role is guaranteed non-null
            String token = client.loginWithJwt(jwt, Objects.requireNonNull(config.getRole()));
            try {
                KvV2Ref ref = KvV2Ref.parse(effectivePath(), config.getEffectiveDefaultMount());
                Map<String, String> data = client.readKvV2(token, ref);
                String fieldName = effectiveField();
                String value = data.get(fieldName);
                if (value == null) {
                    throw new IllegalStateException("field '" + fieldName + "' not found in " + ref
                            + ". Available fields: " + String.join(", ", data.keySet()));
                }
                return Secret.fromString(value);
            } finally {
                client.revokeSelf(token);
            }
        } catch (RuntimeException x) {
            throw x;
        } catch (Exception x) {
            throw new RuntimeException(
                    "Vault JWT secret credentials '" + getId() + "' could not be resolved: " + x.getMessage(), x);
        }
    }

    @Symbol("vaultJwtSecret")
    @Extension
    public static class DescriptorImpl extends BaseStandardCredentialsDescriptor {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Vault JWT secret (fetched per build)";
        }

        public FormValidation doCheckPath(@QueryParameter String value) {
            if (value == null || value.isBlank()) {
                return FormValidation.error("Path is required, e.g. production/db@ops");
            }
            try {
                KvV2Ref.parse(value.trim(), VaultJwtConfig.DEFAULT_MOUNT);
                return FormValidation.ok();
            } catch (IllegalArgumentException x) {
                return FormValidation.error(x.getMessage());
            }
        }

        public FormValidation doCheckField(@QueryParameter String value, @QueryParameter String path) {
            if (value != null && !value.isBlank()) {
                return FormValidation.ok();
            }
            try {
                String inferred = KvV2Ref.splitTrailingField(path == null ? "" : path.trim())[1];
                return FormValidation.ok("Reading field '" + inferred + "' from the end of the path.");
            } catch (IllegalArgumentException x) {
                return FormValidation.error(x.getMessage());
            }
        }
    }
}
