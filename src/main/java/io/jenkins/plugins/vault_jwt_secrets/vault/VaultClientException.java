package io.jenkins.plugins.vault_jwt_secrets.vault;

import java.util.Collections;
import java.util.List;

/**
 * Failure reported by Vault. Carries the HTTP status and Vault's {@code errors[]} strings.
 * Never contains JWTs, client tokens, or secret values.
 */
public final class VaultClientException extends Exception {

    private static final long serialVersionUID = 1L;

    private final int status;
    private final List<String> vaultErrors;

    public VaultClientException(String operation, int status, List<String> vaultErrors) {
        super(operation + " failed: HTTP " + status
                + (vaultErrors.isEmpty() ? "" : " — " + String.join("; ", vaultErrors)));
        this.status = status;
        this.vaultErrors = Collections.unmodifiableList(vaultErrors);
    }

    public int getStatus() {
        return status;
    }

    public List<String> getVaultErrors() {
        return vaultErrors;
    }
}
