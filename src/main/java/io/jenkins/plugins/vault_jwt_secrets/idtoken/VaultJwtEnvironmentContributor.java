package io.jenkins.plugins.vault_jwt_secrets.idtoken;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.EnvVars;
import hudson.Extension;
import hudson.model.EnvironmentContributor;
import hudson.model.Item;
import hudson.model.ItemGroup;
import hudson.model.Job;
import hudson.model.Run;
import hudson.model.TaskListener;

/**
 * Exposes the build's job and folder identity as environment variables so they can be
 * referenced from oidc-provider claim templates (see {@link IdTokenSupplier}). These are
 * <em>always</em> set — to the empty string when not applicable — so that the token's claim
 * templates never fail with an "unsubstituted claim" error.
 *
 * <p>The resulting id token claims are the Jenkins analog of GitLab's {@code project_path} /
 * {@code namespace_path}, letting Vault roles bind on them:
 * <ul>
 *   <li>{@code VAULT_JWT_JOB_PATH} — full job name including folders, e.g. {@code team-a/backend/deploy}</li>
 *   <li>{@code VAULT_JWT_FOLDER_PATH} — full name of the containing folder, e.g. {@code team-a/backend} (empty at root)</li>
 *   <li>{@code VAULT_JWT_JOB_NAME} — the leaf job name, e.g. {@code deploy}</li>
 * </ul>
 */
@Extension
public class VaultJwtEnvironmentContributor extends EnvironmentContributor {

    public static final String ENV_JOB_PATH = "VAULT_JWT_JOB_PATH";
    public static final String ENV_FOLDER_PATH = "VAULT_JWT_FOLDER_PATH";
    public static final String ENV_JOB_NAME = "VAULT_JWT_JOB_NAME";

    @Override
    public void buildEnvironmentFor(@NonNull Run r, @NonNull EnvVars envs, @NonNull TaskListener listener) {
        Job<?, ?> job = r.getParent();
        envs.put(ENV_JOB_PATH, job.getFullName());
        envs.put(ENV_JOB_NAME, job.getName());
        ItemGroup<?> parent = job.getParent();
        envs.put(ENV_FOLDER_PATH, parent instanceof Item ? ((Item) parent).getFullName() : "");
    }
}
