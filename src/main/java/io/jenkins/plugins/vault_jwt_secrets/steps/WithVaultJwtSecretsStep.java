package io.jenkins.plugins.vault_jwt_secrets.steps;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.console.ConsoleLogFilter;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.slaves.WorkspaceList;
import hudson.util.Secret;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultConfigResolver;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultJwtConfig;
import io.jenkins.plugins.vault_jwt_secrets.idtoken.IdTokenSupplier;
import io.jenkins.plugins.vault_jwt_secrets.vault.KvV2Ref;
import io.jenkins.plugins.vault_jwt_secrets.vault.VaultClient;
import io.jenkins.plugins.vault_jwt_secrets.vault.VaultClientException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jenkinsci.plugins.workflow.steps.BodyExecutionCallback;
import org.jenkinsci.plugins.workflow.steps.BodyInvoker;
import org.jenkinsci.plugins.workflow.steps.EnvironmentExpander;
import org.jenkinsci.plugins.workflow.steps.GeneralNonBlockingStepExecution;
import org.jenkinsci.plugins.workflow.steps.Step;
import org.jenkinsci.plugins.workflow.steps.StepContext;
import org.jenkinsci.plugins.workflow.steps.StepDescriptor;
import org.jenkinsci.plugins.workflow.steps.StepExecution;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;

/**
 * Block step that logs into Vault with a per-build JWT, fetches the requested KV v2 secrets,
 * exposes them as environment variables (or temp files) inside the block only, and masks
 * their values in the console log. The Jenkins analog of GitLab CI's {@code secrets:vault:}.
 */
public class WithVaultJwtSecretsStep extends Step {

    private final List<VaultSecretSpec> secrets;
    private String role;
    private String vaultUrl;
    private String authPath;
    private String namespace;
    private String audience;
    private String idTokenCredentialsId;

    @DataBoundConstructor
    public WithVaultJwtSecretsStep(@CheckForNull List<VaultSecretSpec> secrets) {
        this.secrets = secrets == null ? new ArrayList<>() : new ArrayList<>(secrets);
    }

    public List<VaultSecretSpec> getSecrets() {
        return secrets;
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

    @CheckForNull
    public String getIdTokenCredentialsId() {
        return idTokenCredentialsId;
    }

    @DataBoundSetter
    public void setIdTokenCredentialsId(String idTokenCredentialsId) {
        this.idTokenCredentialsId = idTokenCredentialsId;
    }

    VaultJwtConfig toOverrides() {
        return VaultJwtConfig.builder()
                .vaultUrl(vaultUrl)
                .authPath(authPath)
                .role(role)
                .namespace(namespace)
                .audience(audience)
                .idTokenCredentialsId(idTokenCredentialsId)
                .build();
    }

    @Override
    public StepExecution start(StepContext context) {
        return new Execution(this, context);
    }

    static class Execution extends GeneralNonBlockingStepExecution {

        private static final long serialVersionUID = 1L;

        private final transient WithVaultJwtSecretsStep step;

        Execution(WithVaultJwtSecretsStep step, StepContext context) {
            super(context);
            this.step = step;
        }

        @Override
        public boolean start() throws Exception {
            run(this::doStart);
            return false;
        }

        private void doStart() throws Exception {
            Run<?, ?> run = getContext().get(Run.class);
            TaskListener listener = getContext().get(TaskListener.class);
            if (step.getSecrets().isEmpty()) {
                throw new AbortException(
                        "withVaultJwtSecrets: no secrets requested — pass secrets: [vaultSecret(...)]");
            }
            Set<String> vars = new HashSet<>();
            for (VaultSecretSpec spec : step.getSecrets()) {
                if (!VaultSecretSpec.ENV_NAME.matcher(spec.getVar()).matches()) {
                    throw new AbortException(
                            "withVaultJwtSecrets: '" + spec.getVar() + "' is not a valid environment variable name");
                }
                if (!vars.add(spec.getVar())) {
                    throw new AbortException("withVaultJwtSecrets: variable '" + spec.getVar() + "' is used twice");
                }
                try {
                    spec.effectiveField();
                } catch (IllegalArgumentException x) {
                    throw new AbortException("withVaultJwtSecrets: " + x.getMessage());
                }
            }
            // ${VAR} references in the connection settings (audience, vaultUrl, role, ...) are expanded
            // against the build environment, so a Jenkinsfile can parameterise them like oidc-provider does.
            VaultJwtConfig config = VaultConfigResolver.resolve(
                    run, step.toOverrides(), getContext().get(EnvVars.class));

            Map<String, String> env = new LinkedHashMap<>();
            List<String> secretValues = new ArrayList<>();
            String tempDirName = null;

            String jwt = IdTokenSupplier.mintForBuild(run, config);
            VaultClient client = new VaultClient(config);
            String token;
            try {
                token = client.loginWithJwt(jwt, config.getRole());
            } catch (VaultClientException x) {
                throw new AbortException("withVaultJwtSecrets: " + x.getMessage()
                        + " — check the Vault role's bound_audiences/bound_claims and that Vault can reach"
                        + " the Jenkins OIDC discovery endpoint.");
            }
            try {
                Map<KvV2Ref, Map<String, String>> fetched = new HashMap<>();
                for (VaultSecretSpec spec : step.getSecrets()) {
                    KvV2Ref ref = KvV2Ref.parse(spec.effectivePath(), config.getEffectiveDefaultMount());
                    String fieldName = spec.effectiveField();
                    Map<String, String> data = fetched.get(ref);
                    if (data == null) {
                        try {
                            data = client.readKvV2(token, ref);
                        } catch (VaultClientException x) {
                            throw new AbortException("withVaultJwtSecrets: " + x.getMessage());
                        }
                        fetched.put(ref, data);
                    }
                    String value = data.get(fieldName);
                    if (value == null) {
                        throw new AbortException("withVaultJwtSecrets: field '" + fieldName + "' not found in " + ref
                                + ". Available fields: " + String.join(", ", data.keySet()));
                    }
                    secretValues.add(value);
                    if (spec.isFile()) {
                        if (tempDirName == null) {
                            tempDirName = "withVaultJwtSecrets-" + UUID.randomUUID();
                        }
                        FilePath file = tempDir(getContext(), tempDirName).child(spec.getVar());
                        file.write(value, "UTF-8");
                        file.chmod(0600);
                        env.put(spec.getVar(), file.getRemote());
                    } else {
                        env.put(spec.getVar(), value);
                    }
                }
            } finally {
                client.revokeSelf(token);
            }

            listener.getLogger()
                    .println("[withVaultJwtSecrets] Fetched " + env.size() + " secret(s) from " + config.getVaultUrl()
                            + " (role: " + config.getRole() + "); values are masked below.");

            getContext()
                    .newBodyInvoker()
                    .withContext(
                            EnvironmentExpander.merge(getContext().get(EnvironmentExpander.class), new Overrider(env)))
                    .withContext(BodyInvoker.mergeConsoleLogFilters(
                            getContext().get(ConsoleLogFilter.class),
                            new MaskingConsoleLogFilter(run.getCharset().name(), secretValues)))
                    .withCallback(new Callback(tempDirName))
                    .start();
        }

        private static FilePath tempDir(StepContext context, String dirName) throws Exception {
            FilePath workspace = context.get(FilePath.class);
            if (workspace == null) {
                throw new AbortException("withVaultJwtSecrets: file-type secrets require a node/workspace context;"
                        + " wrap the step in node { } or use type: 'env'");
            }
            FilePath base = WorkspaceList.tempDir(workspace);
            if (base == null) {
                throw new AbortException("withVaultJwtSecrets: could not resolve a temp directory for the workspace");
            }
            FilePath dir = base.child(dirName);
            dir.mkdirs();
            dir.chmod(0700);
            return dir;
        }
    }

    private static final class Overrider extends EnvironmentExpander {

        private static final long serialVersionUID = 1L;

        private final Map<String, Secret> overrides = new LinkedHashMap<>();

        Overrider(Map<String, String> env) {
            env.forEach((key, value) -> overrides.put(key, Secret.fromString(value)));
        }

        @Override
        public void expand(@NonNull EnvVars env) {
            overrides.forEach((key, value) -> env.override(key, value.getPlainText()));
        }

        @Override
        public Set<String> getSensitiveVariables() {
            return overrides.keySet();
        }
    }

    private static final class Callback extends BodyExecutionCallback.TailCall {

        private static final long serialVersionUID = 1L;
        private static final Logger LOGGER = Logger.getLogger(WithVaultJwtSecretsStep.class.getName());

        private final @CheckForNull String tempDirName;

        Callback(@CheckForNull String tempDirName) {
            this.tempDirName = tempDirName;
        }

        @Override
        protected void finished(StepContext context) {
            if (tempDirName == null) {
                return;
            }
            try {
                FilePath workspace = context.get(FilePath.class);
                FilePath base = workspace == null ? null : WorkspaceList.tempDir(workspace);
                if (base != null) {
                    base.child(tempDirName).deleteRecursive();
                }
            } catch (Exception x) {
                LOGGER.log(Level.WARNING, "Could not delete Vault secret temp directory " + tempDirName, x);
            }
        }
    }

    @Extension
    public static class DescriptorImpl extends StepDescriptor {

        @Override
        public String getFunctionName() {
            return "withVaultJwtSecrets";
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "Fetch Vault secrets with a per-build JWT";
        }

        @Override
        public boolean takesImplicitBlockArgument() {
            return true;
        }

        @Override
        public Set<? extends Class<?>> getRequiredContext() {
            return Set.of(Run.class, TaskListener.class);
        }
    }
}
