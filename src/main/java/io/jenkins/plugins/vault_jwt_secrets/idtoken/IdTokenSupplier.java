package io.jenkins.plugins.vault_jwt_secrets.idtoken;

import com.cloudbees.plugins.credentials.Credentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.AbortException;
import hudson.model.Run;
import io.jenkins.plugins.oidc_provider.IdTokenStringCredentials;
import io.jenkins.plugins.oidc_provider.config.ClaimTemplate;
import io.jenkins.plugins.oidc_provider.config.IdTokenConfiguration;
import io.jenkins.plugins.oidc_provider.config.StringClaimType;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultJwtConfig;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Obtains per-build ID tokens from the oidc-provider plugin without manual credential setup.
 * One {@link IdTokenStringCredentials} is lazily provisioned per audience in the system credential
 * store (global domain, default issuer — both required for the root JWKS endpoint at
 * {@code {JENKINS_URL}oidc/jwks} to serve its public key). An explicitly configured
 * {@code idTokenCredentialsId} bypasses auto-provisioning.
 */
public final class IdTokenSupplier {

    private static final Logger LOGGER = Logger.getLogger(IdTokenSupplier.class.getName());

    public static final String CREDENTIALS_ID_PREFIX = "vault-jwt-secrets-idtoken-";

    private IdTokenSupplier() {}

    /** Mints an ID token carrying build claims ({@code sub} = job URL, {@code build_number}, ...). */
    @NonNull
    public static String mintForBuild(@NonNull Run<?, ?> run, @NonNull VaultJwtConfig config) throws IOException {
        String id = credentialsId(config);
        IdTokenStringCredentials credentials =
                CredentialsProvider.findCredentialById(id, IdTokenStringCredentials.class, run);
        if (credentials == null) {
            throw new AbortException("Could not find id token credentials '" + id
                    + "'. If you configured an explicit idTokenCredentialsId, check that it exists and is an"
                    + " 'OpenID Connect id token' credential visible to this job.");
        }
        return credentials.getSecret().getPlainText();
    }

    /** Mints an ID token with non-build claims ({@code sub} = Jenkins URL); used by connectivity tests. */
    @NonNull
    public static String mintGlobal(@NonNull VaultJwtConfig config) throws IOException {
        String id = credentialsId(config);
        for (Credentials c : SystemCredentialsProvider.getInstance().getCredentials()) {
            if (c instanceof IdTokenStringCredentials && id.equals(((IdTokenStringCredentials) c).getId())) {
                return ((IdTokenStringCredentials) c).getSecret().getPlainText();
            }
        }
        throw new AbortException("Could not find id token credentials '" + id + "'");
    }

    private static String credentialsId(VaultJwtConfig config) throws IOException {
        String explicit = config.getIdTokenCredentialsId();
        if (explicit != null && !explicit.isBlank()) {
            return explicit;
        }
        String audience = config.getEffectiveAudience();
        if (audience == null || audience.isBlank()) {
            throw new AbortException("Cannot determine the id token audience: no Vault URL or audience configured");
        }
        return getOrCreateIdTokenCredentials(audience);
    }

    /**
     * Returns the ID of the auto-provisioned id token credential for {@code audience},
     * creating it on first use. The ID is deterministic so concurrent builds converge
     * on one credential (= one signing keypair / JWKS entry) per audience.
     */
    @NonNull
    public static synchronized String getOrCreateIdTokenCredentials(@NonNull String audience) throws IOException {
        String id = CREDENTIALS_ID_PREFIX + sha256Prefix(audience);
        SystemCredentialsProvider provider = SystemCredentialsProvider.getInstance();
        for (Credentials c : provider.getCredentials()) {
            if (c instanceof IdTokenStringCredentials && id.equals(((IdTokenStringCredentials) c).getId())) {
                return id;
            }
        }
        IdTokenStringCredentials credentials = new IdTokenStringCredentials(
                CredentialsScope.GLOBAL, id, "Vault JWT Secrets: auto-provisioned id token (aud: " + audience + ")");
        credentials.setAudience(audience);
        // issuer intentionally left null: only default-issuer credentials are served by the root JWKS
        provider.getCredentials().add(credentials);
        provider.save();
        ensureBuildClaimTemplates();
        LOGGER.log(Level.INFO, "Provisioned id token credentials {0} for audience {1}", new Object[] {id, audience});
        return id;
    }

    /**
     * Enriches oidc-provider's build id tokens with job/folder identity claims (the Jenkins analog of
     * GitLab's {@code project_path} / {@code namespace_path}), so Vault roles can bind on them. Claims are
     * added additively and idempotently: any claim name the administrator already defined is left untouched.
     * Backed by {@link VaultJwtEnvironmentContributor}, which guarantees these variables are always set.
     */
    static synchronized void ensureBuildClaimTemplates() {
        Map<String, String> desired = new LinkedHashMap<>();
        desired.put("job_path", "${" + VaultJwtEnvironmentContributor.ENV_JOB_PATH + "}");
        desired.put("folder_path", "${" + VaultJwtEnvironmentContributor.ENV_FOLDER_PATH + "}");
        desired.put("job_name", "${" + VaultJwtEnvironmentContributor.ENV_JOB_NAME + "}");
        desired.put("job_url", "${JOB_URL}");
        desired.put("build_url", "${BUILD_URL}");

        IdTokenConfiguration config = IdTokenConfiguration.get();
        List<ClaimTemplate> templates = new ArrayList<>(config.getBuildClaimTemplates());
        boolean changed = false;
        for (ClaimTemplate existing : templates) {
            desired.remove(existing.name);
        }
        for (Map.Entry<String, String> e : desired.entrySet()) {
            templates.add(new ClaimTemplate(e.getKey(), e.getValue(), new StringClaimType()));
            changed = true;
        }
        if (changed) {
            config.setBuildClaimTemplates(templates);
            config.save();
            LOGGER.log(
                    Level.INFO, "Added Vault job identity claims to oidc-provider build tokens: {0}", desired.keySet());
        }
    }

    @CheckForNull
    public static String defaultCredentialsIdFor(@NonNull String audience) {
        try {
            return CREDENTIALS_ID_PREFIX + sha256Prefix(audience);
        } catch (IOException x) {
            return null;
        }
    }

    private static String sha256Prefix(String audience) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(audience.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                hex.append(String.format("%02x", hash[i]));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException x) {
            throw new IOException(x);
        }
    }
}
