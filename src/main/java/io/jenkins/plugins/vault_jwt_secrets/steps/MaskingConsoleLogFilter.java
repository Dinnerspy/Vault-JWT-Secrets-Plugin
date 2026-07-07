package io.jenkins.plugins.vault_jwt_secrets.steps;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.console.ConsoleLogFilter;
import hudson.console.LineTransformationOutputStream;
import hudson.model.Run;
import hudson.util.Secret;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;
import org.jenkinsci.plugins.credentialsbinding.masking.SecretPatterns;

/**
 * Replaces secret values (and their Base64/URL-encoded forms, via credentials-binding's
 * {@link SecretPatterns}) with {@code ****} in the console log. Values are held as
 * {@link Secret} so nothing lands in plaintext when the filter is persisted with the flow.
 */
public final class MaskingConsoleLogFilter extends ConsoleLogFilter implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String charsetName;
    private final List<Secret> values;
    private transient Pattern pattern;

    public MaskingConsoleLogFilter(@NonNull String charsetName, @NonNull Collection<String> secretValues) {
        this.charsetName = charsetName;
        this.values = new ArrayList<>();
        for (String value : secretValues) {
            if (value != null && !value.isEmpty()) {
                values.add(Secret.fromString(value));
            }
        }
    }

    private synchronized Pattern pattern() {
        if (pattern == null) {
            List<String> plaintexts = new ArrayList<>();
            for (Secret secret : values) {
                plaintexts.add(secret.getPlainText());
            }
            pattern = SecretPatterns.getAggregateSecretPattern(plaintexts);
        }
        return pattern;
    }

    @Override
    public OutputStream decorateLogger(Run build, OutputStream logger) {
        if (values.isEmpty()) {
            return logger;
        }
        return new LineTransformationOutputStream.Delegating(logger) {
            @Override
            protected void eol(byte[] b, int len) throws IOException {
                String line = new String(b, 0, len, charsetName);
                out.write(pattern().matcher(line).replaceAll("****").getBytes(charsetName));
            }
        };
    }
}
