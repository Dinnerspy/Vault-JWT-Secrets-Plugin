package io.jenkins.plugins.vault_jwt_secrets.config;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.util.FormValidation;
import io.jenkins.plugins.vault_jwt_secrets.idtoken.IdTokenSupplier;
import io.jenkins.plugins.vault_jwt_secrets.vault.VaultClient;
import io.jenkins.plugins.vault_jwt_secrets.vault.VaultClientException;
import java.net.URI;
import jenkins.model.GlobalConfiguration;
import jenkins.model.Jenkins;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.interceptor.RequirePOST;
import org.kohsuke.stapler.verb.POST;

/** Instance-wide defaults for the Vault JWT Secrets plugin (Manage Jenkins » System). */
@Symbol("vaultJwtSecrets")
@Extension
public class VaultJwtGlobalConfiguration extends GlobalConfiguration {

    private String vaultUrl;
    private String authPath;
    private String role;
    private String namespace;
    private String defaultMount;
    private String caCertificatePem;
    private boolean skipTlsVerify;
    private String audience;
    private String idTokenCredentialsId;

    public VaultJwtGlobalConfiguration() {
        load();
    }

    @NonNull
    public static VaultJwtGlobalConfiguration get() {
        return GlobalConfiguration.all().getInstance(VaultJwtGlobalConfiguration.class);
    }

    @NonNull
    public VaultJwtConfig toConfig() {
        return VaultJwtConfig.builder()
                .vaultUrl(vaultUrl)
                .authPath(authPath)
                .role(role)
                .namespace(namespace)
                .defaultMount(defaultMount)
                .caCertificatePem(caCertificatePem)
                .skipTlsVerify(skipTlsVerify ? Boolean.TRUE : null)
                .audience(audience)
                .idTokenCredentialsId(idTokenCredentialsId)
                .build();
    }

    @CheckForNull
    public String getVaultUrl() {
        return vaultUrl;
    }

    @DataBoundSetter
    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = trimToNull(vaultUrl);
        save();
    }

    @CheckForNull
    public String getAuthPath() {
        return authPath;
    }

    @DataBoundSetter
    public void setAuthPath(String authPath) {
        this.authPath = trimToNull(authPath);
        save();
    }

    @CheckForNull
    public String getRole() {
        return role;
    }

    @DataBoundSetter
    public void setRole(String role) {
        this.role = trimToNull(role);
        save();
    }

    @CheckForNull
    public String getNamespace() {
        return namespace;
    }

    @DataBoundSetter
    public void setNamespace(String namespace) {
        this.namespace = trimToNull(namespace);
        save();
    }

    @CheckForNull
    public String getDefaultMount() {
        return defaultMount;
    }

    @DataBoundSetter
    public void setDefaultMount(String defaultMount) {
        this.defaultMount = trimToNull(defaultMount);
        save();
    }

    @CheckForNull
    public String getCaCertificatePem() {
        return caCertificatePem;
    }

    @DataBoundSetter
    public void setCaCertificatePem(String caCertificatePem) {
        this.caCertificatePem = trimToNull(caCertificatePem);
        save();
    }

    public boolean isSkipTlsVerify() {
        return skipTlsVerify;
    }

    @DataBoundSetter
    public void setSkipTlsVerify(boolean skipTlsVerify) {
        this.skipTlsVerify = skipTlsVerify;
        save();
    }

    @CheckForNull
    public String getAudience() {
        return audience;
    }

    @DataBoundSetter
    public void setAudience(String audience) {
        this.audience = trimToNull(audience);
        save();
    }

    @CheckForNull
    public String getIdTokenCredentialsId() {
        return idTokenCredentialsId;
    }

    @DataBoundSetter
    public void setIdTokenCredentialsId(String idTokenCredentialsId) {
        this.idTokenCredentialsId = trimToNull(idTokenCredentialsId);
        save();
    }

    @POST
    public FormValidation doCheckVaultUrl(@QueryParameter String value) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        if (value == null || value.isBlank()) {
            return FormValidation.ok();
        }
        try {
            URI uri = new URI(value.trim());
            if (uri.getScheme() == null || uri.getHost() == null) {
                return FormValidation.error("Not a valid URL");
            }
            if ("http".equals(uri.getScheme())) {
                return FormValidation.warning("Plain HTTP: the JWT and secrets travel unencrypted. Use HTTPS.");
            }
            if (!"https".equals(uri.getScheme())) {
                return FormValidation.error("URL must use http or https");
            }
            return FormValidation.ok();
        } catch (Exception x) {
            return FormValidation.error("Not a valid URL: " + x.getMessage());
        }
    }

    @POST
    public FormValidation doCheckSkipTlsVerify(@QueryParameter boolean value) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        return value
                ? FormValidation.warning(
                        "TLS certificate verification is disabled. Anyone on the network can impersonate Vault."
                                + " Use the CA certificate field instead.")
                : FormValidation.ok();
    }

    @RequirePOST
    public FormValidation doTestConnection(
            @QueryParameter String vaultUrl,
            @QueryParameter String authPath,
            @QueryParameter String role,
            @QueryParameter String namespace,
            @QueryParameter String caCertificatePem,
            @QueryParameter boolean skipTlsVerify,
            @QueryParameter String audience) {
        Jenkins.get().checkPermission(Jenkins.ADMINISTER);
        VaultJwtConfig config = VaultJwtConfig.builder()
                .vaultUrl(trimToNull(vaultUrl))
                .authPath(trimToNull(authPath))
                .role(trimToNull(role))
                .namespace(trimToNull(namespace))
                .caCertificatePem(trimToNull(caCertificatePem))
                .skipTlsVerify(skipTlsVerify ? Boolean.TRUE : null)
                .audience(trimToNull(audience))
                .build();
        if (config.getVaultUrl() == null) {
            return FormValidation.error("Vault URL is required");
        }
        try {
            VaultClient client = new VaultClient(config);
            client.healthCheck();
            if (config.getRole() == null) {
                return FormValidation.ok("Vault is reachable. Enter a role to also test JWT login.");
            }
            String jwt = IdTokenSupplier.mintGlobal(config);
            String token = client.loginWithJwt(jwt, config.getRole());
            client.revokeSelf(token);
            return FormValidation.ok("Success: Vault is reachable and JWT login for role '" + config.getRole()
                    + "' works. Note: build tokens carry a different sub claim (the job URL), so Vault roles"
                    + " with bound_claims on sub may still reject or accept differently during builds.");
        } catch (VaultClientException x) {
            return FormValidation.error("Vault said: " + x.getMessage()
                    + ". If this is a JWT verification error, confirm Vault can reach "
                    + Jenkins.get().getRootUrl() + "oidc/.well-known/openid-configuration");
        } catch (Exception x) {
            return FormValidation.error("Connection failed: " + x.getMessage());
        }
    }

    @CheckForNull
    private static String trimToNull(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}
