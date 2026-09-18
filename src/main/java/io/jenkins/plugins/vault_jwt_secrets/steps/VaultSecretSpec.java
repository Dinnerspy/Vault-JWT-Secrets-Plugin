package io.jenkins.plugins.vault_jwt_secrets.steps;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.util.FormValidation;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultJwtConfig;
import io.jenkins.plugins.vault_jwt_secrets.vault.KvV2Ref;
import java.io.Serializable;
import java.util.regex.Pattern;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

/** One secret to fetch: which KV v2 path and field, and the environment variable to expose it as. */
public class VaultSecretSpec extends AbstractDescribableImpl<VaultSecretSpec> implements Serializable {

    private static final long serialVersionUID = 1L;

    public static final String TYPE_ENV = "env";
    public static final String TYPE_FILE = "file";

    static final Pattern ENV_NAME = Pattern.compile("[A-Za-z_][A-Za-z0-9_]*");

    private final String path;
    private final String var;
    private String field;
    private String type = TYPE_ENV;

    @DataBoundConstructor
    public VaultSecretSpec(@NonNull String path, @NonNull String var) {
        this.path = path.trim();
        this.var = var.trim();
    }

    public String getPath() {
        return path;
    }

    @CheckForNull
    public String getField() {
        return field;
    }

    @DataBoundSetter
    public void setField(String field) {
        this.field = field == null ? null : field.trim();
    }

    /**
     * The secret path with the field stripped off. With an explicit {@code field} this is just
     * {@code path}; otherwise GitLab's one-line form applies and the last segment is the field.
     */
    @NonNull
    public String effectivePath() {
        return hasExplicitField() ? path : KvV2Ref.splitTrailingField(path)[0];
    }

    /** The field to read: the explicit one, else the last segment of {@code path} (GitLab's form). */
    @NonNull
    public String effectiveField() {
        return hasExplicitField() ? field : KvV2Ref.splitTrailingField(path)[1];
    }

    private boolean hasExplicitField() {
        return field != null && !field.isBlank();
    }

    public String getVar() {
        return var;
    }

    public String getType() {
        return type;
    }

    @DataBoundSetter
    public void setType(String type) {
        if (!TYPE_ENV.equals(type) && !TYPE_FILE.equals(type)) {
            throw new IllegalArgumentException("type must be '" + TYPE_ENV + "' or '" + TYPE_FILE + "'");
        }
        this.type = type;
    }

    public boolean isFile() {
        return TYPE_FILE.equals(type);
    }

    @Override
    public String toString() {
        return "vaultSecret(path: " + path + (hasExplicitField() ? ", field: " + field : "") + ", var: " + var
                + ", type: " + type + ")";
    }

    @Symbol("vaultSecret")
    @Extension
    public static class DescriptorImpl extends Descriptor<VaultSecretSpec> {

        @NonNull
        @Override
        public String getDisplayName() {
            return "Vault secret";
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

        public FormValidation doCheckVar(@QueryParameter String value) {
            if (value == null || value.isBlank()) {
                return FormValidation.error("Variable name is required");
            }
            return ENV_NAME.matcher(value.trim()).matches()
                    ? FormValidation.ok()
                    : FormValidation.error("Not a valid environment variable name");
        }
    }
}
