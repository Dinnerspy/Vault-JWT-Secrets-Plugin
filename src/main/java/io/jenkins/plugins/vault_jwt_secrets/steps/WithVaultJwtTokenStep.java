package io.jenkins.plugins.vault_jwt_secrets.steps;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.console.ConsoleLogFilter;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.Secret;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultConfigResolver;
import io.jenkins.plugins.vault_jwt_secrets.config.VaultJwtConfig;
import io.jenkins.plugins.vault_jwt_secrets.idtoken.IdTokenSupplier;
import java.util.List;
import java.util.Set;
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
 * Block step that mints a per-build ID token and exposes the raw JWT as an environment variable inside
 * the block, masked in the console log. The Jenkins analog of GitLab CI's {@code id_tokens:} — use it
 * when you want to drive the Vault login yourself (or hand the token to another OIDC-trusting service)
 * instead of letting {@code withVaultJwtSecrets} fetch secrets for you.
 *
 * <p>{@code audience} accepts {@code ${VAR}} references, expanded against the build environment.
 */
public class WithVaultJwtTokenStep extends Step {

    /** Default name of the environment variable holding the token. */
    public static final String DEFAULT_VARIABLE = "VAULT_ID_TOKEN";

    private String variable;
    private String audience;
    private String vaultUrl;
    private String idTokenCredentialsId;

    @DataBoundConstructor
    public WithVaultJwtTokenStep() {}

    @CheckForNull
    public String getVariable() {
        return variable;
    }

    @DataBoundSetter
    public void setVariable(String variable) {
        this.variable = variable;
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
    public String getVaultUrl() {
        return vaultUrl;
    }

    @DataBoundSetter
    public void setVaultUrl(String vaultUrl) {
        this.vaultUrl = vaultUrl;
    }

    @CheckForNull
    public String getIdTokenCredentialsId() {
        return idTokenCredentialsId;
    }

    @DataBoundSetter
    public void setIdTokenCredentialsId(String idTokenCredentialsId) {
        this.idTokenCredentialsId = idTokenCredentialsId;
    }

    @NonNull
    String effectiveVariable() {
        return variable == null || variable.isBlank() ? DEFAULT_VARIABLE : variable;
    }

    VaultJwtConfig toOverrides() {
        return VaultJwtConfig.builder()
                .vaultUrl(vaultUrl)
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

        private final transient WithVaultJwtTokenStep step;

        Execution(WithVaultJwtTokenStep step, StepContext context) {
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
            String var = step.effectiveVariable();
            if (!VaultSecretSpec.ENV_NAME.matcher(var).matches()) {
                throw new AbortException("withVaultJwtToken: '" + var + "' is not a valid environment variable name");
            }
            // Only the audience matters here, so vaultUrl/role are not required — a job may want a
            // token for a service that is not Vault at all.
            VaultJwtConfig config = VaultConfigResolver.resolveForToken(
                    run, step.toOverrides(), getContext().get(EnvVars.class));
            String audience = config.getEffectiveAudience();
            if (audience == null || audience.isBlank()) {
                throw new AbortException("withVaultJwtToken: no audience. Pass audience: '...' (a ${VAR} reference"
                        + " is expanded against the build environment), or configure a Vault URL on the folder"
                        + " or globally so the audience can default to it.");
            }
            String jwt = IdTokenSupplier.mintForBuild(run, config);

            listener.getLogger()
                    .println("[withVaultJwtToken] Minted a per-build id token for audience " + audience
                            + "; available as $" + var + " (masked).");

            getContext()
                    .newBodyInvoker()
                    .withContext(EnvironmentExpander.merge(
                            getContext().get(EnvironmentExpander.class), new TokenExpander(var, jwt)))
                    .withContext(BodyInvoker.mergeConsoleLogFilters(
                            getContext().get(ConsoleLogFilter.class),
                            new MaskingConsoleLogFilter(run.getCharset().name(), List.of(jwt))))
                    .withCallback(BodyExecutionCallback.wrap(getContext()))
                    .start();
        }
    }

    private static final class TokenExpander extends EnvironmentExpander {

        private static final long serialVersionUID = 1L;

        private final String variable;
        private final Secret token;

        TokenExpander(String variable, String token) {
            this.variable = variable;
            this.token = Secret.fromString(token);
        }

        @Override
        public void expand(@NonNull EnvVars env) {
            env.override(variable, token.getPlainText());
        }

        @Override
        public Set<String> getSensitiveVariables() {
            return Set.of(variable);
        }
    }

    @Extension
    public static class DescriptorImpl extends StepDescriptor {

        @Override
        public String getFunctionName() {
            return "withVaultJwtToken";
        }

        @NonNull
        @Override
        public String getDisplayName() {
            return "Expose a per-build Vault id token (JWT)";
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
