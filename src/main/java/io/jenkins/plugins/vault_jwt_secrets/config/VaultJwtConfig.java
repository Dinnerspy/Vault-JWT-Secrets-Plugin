package io.jenkins.plugins.vault_jwt_secrets.config;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Util;
import java.io.Serializable;
import java.util.Map;

/**
 * Effective Vault connection settings. All fields are nullable so that partially filled
 * instances can act as override layers; {@link #mergedWith} lets an inner layer
 * (folder property, step parameters) win over an outer one (global configuration).
 */
public final class VaultJwtConfig implements Serializable {

    private static final long serialVersionUID = 1L;

    public static final String DEFAULT_AUTH_PATH = "jwt";
    public static final String DEFAULT_MOUNT = "secret";

    private final @CheckForNull String vaultUrl;
    private final @CheckForNull String authPath;
    private final @CheckForNull String role;
    private final @CheckForNull String namespace;
    private final @CheckForNull String defaultMount;
    private final @CheckForNull String caCertificatePem;
    private final @CheckForNull Boolean skipTlsVerify;
    private final @CheckForNull String audience;
    private final @CheckForNull String idTokenCredentialsId;

    private VaultJwtConfig(Builder b) {
        this.vaultUrl = b.vaultUrl;
        this.authPath = b.authPath;
        this.role = b.role;
        this.namespace = b.namespace;
        this.defaultMount = b.defaultMount;
        this.caCertificatePem = b.caCertificatePem;
        this.skipTlsVerify = b.skipTlsVerify;
        this.audience = b.audience;
        this.idTokenCredentialsId = b.idTokenCredentialsId;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Returns a config in which every non-empty field of {@code override} replaces this one's. */
    @NonNull
    public VaultJwtConfig mergedWith(@CheckForNull VaultJwtConfig override) {
        if (override == null) {
            return this;
        }
        Builder b = new Builder();
        b.vaultUrl = pick(override.vaultUrl, vaultUrl);
        b.authPath = pick(override.authPath, authPath);
        b.role = pick(override.role, role);
        b.namespace = pick(override.namespace, namespace);
        b.defaultMount = pick(override.defaultMount, defaultMount);
        b.caCertificatePem = pick(override.caCertificatePem, caCertificatePem);
        b.skipTlsVerify = override.skipTlsVerify != null ? override.skipTlsVerify : skipTlsVerify;
        b.audience = pick(override.audience, audience);
        b.idTokenCredentialsId = pick(override.idTokenCredentialsId, idTokenCredentialsId);
        return new VaultJwtConfig(b);
    }

    private static String pick(@CheckForNull String inner, @CheckForNull String outer) {
        return inner != null && !inner.isBlank() ? inner : outer;
    }

    /**
     * Returns a config in which {@code ${VAR}} references in the connection settings are replaced with
     * values from the build environment, so that e.g. {@code audience: '${VAULT_ADDR}'} works the same
     * way the oidc-provider plugin substitutes variables into its claim templates. Unknown variables are
     * left untouched. The CA certificate is deliberately not expanded — PEM text is data, not a template.
     */
    @NonNull
    public VaultJwtConfig expandedWith(@CheckForNull Map<String, String> env) {
        if (env == null || env.isEmpty()) {
            return this;
        }
        Builder b = new Builder();
        b.vaultUrl = Util.replaceMacro(vaultUrl, env);
        b.authPath = Util.replaceMacro(authPath, env);
        b.role = Util.replaceMacro(role, env);
        b.namespace = Util.replaceMacro(namespace, env);
        b.defaultMount = Util.replaceMacro(defaultMount, env);
        b.caCertificatePem = caCertificatePem;
        b.skipTlsVerify = skipTlsVerify;
        b.audience = Util.replaceMacro(audience, env);
        b.idTokenCredentialsId = Util.replaceMacro(idTokenCredentialsId, env);
        return new VaultJwtConfig(b);
    }

    @CheckForNull
    public String getVaultUrl() {
        return vaultUrl;
    }

    @CheckForNull
    public String getRole() {
        return role;
    }

    @CheckForNull
    public String getNamespace() {
        return namespace;
    }

    @CheckForNull
    public String getCaCertificatePem() {
        return caCertificatePem;
    }

    @CheckForNull
    public String getIdTokenCredentialsId() {
        return idTokenCredentialsId;
    }

    public boolean isSkipTlsVerify() {
        return Boolean.TRUE.equals(skipTlsVerify);
    }

    @NonNull
    public String getEffectiveAuthPath() {
        return authPath == null || authPath.isBlank() ? DEFAULT_AUTH_PATH : authPath;
    }

    @NonNull
    public String getEffectiveDefaultMount() {
        return defaultMount == null || defaultMount.isBlank() ? DEFAULT_MOUNT : defaultMount;
    }

    /** Audience for the id token; defaults to the Vault URL, matching GitLab's convention. */
    @CheckForNull
    public String getEffectiveAudience() {
        return audience != null && !audience.isBlank() ? audience : vaultUrl;
    }

    public static final class Builder {
        private String vaultUrl;
        private String authPath;
        private String role;
        private String namespace;
        private String defaultMount;
        private String caCertificatePem;
        private Boolean skipTlsVerify;
        private String audience;
        private String idTokenCredentialsId;

        public Builder vaultUrl(String v) {
            this.vaultUrl = v;
            return this;
        }

        public Builder authPath(String v) {
            this.authPath = v;
            return this;
        }

        public Builder role(String v) {
            this.role = v;
            return this;
        }

        public Builder namespace(String v) {
            this.namespace = v;
            return this;
        }

        public Builder defaultMount(String v) {
            this.defaultMount = v;
            return this;
        }

        public Builder caCertificatePem(String v) {
            this.caCertificatePem = v;
            return this;
        }

        public Builder skipTlsVerify(Boolean v) {
            this.skipTlsVerify = v;
            return this;
        }

        public Builder audience(String v) {
            this.audience = v;
            return this;
        }

        public Builder idTokenCredentialsId(String v) {
            this.idTokenCredentialsId = v;
            return this;
        }

        public VaultJwtConfig build() {
            return new VaultJwtConfig(this);
        }
    }
}
