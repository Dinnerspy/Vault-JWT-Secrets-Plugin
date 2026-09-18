package io.jenkins.plugins.vault_jwt_secrets.vault;

import edu.umd.cs.findbugs.annotations.NonNull;
import java.io.Serializable;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Reference to a KV v2 secret in GitLab notation: {@code path/to/secret@mount}.
 * When {@code @mount} is omitted the configured default mount applies.
 */
public final class KvV2Ref implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String mount;
    private final String path;

    private KvV2Ref(String mount, String path) {
        this.mount = mount;
        this.path = path;
    }

    public static KvV2Ref parse(@NonNull String spec, @NonNull String defaultMount) {
        String mount;
        String path;
        int at = spec.lastIndexOf('@');
        if (at >= 0) {
            path = spec.substring(0, at);
            mount = spec.substring(at + 1);
        } else {
            path = spec;
            mount = defaultMount;
        }
        validateSegment("mount", mount);
        if (path.isBlank()) {
            throw new IllegalArgumentException("Secret path must not be empty in '" + spec + "'");
        }
        if (path.startsWith("/") || path.endsWith("/")) {
            throw new IllegalArgumentException("Secret path must not start or end with '/' in '" + spec + "'");
        }
        for (String segment : path.split("/", -1)) {
            validateSegment("path segment", segment);
        }
        return new KvV2Ref(mount, path);
    }

    /**
     * Splits GitLab's one-line secret notation, in which the last path segment names the field:
     * {@code production/db/password@ops} → {@code ["production/db@ops", "password"]}. Used when no
     * explicit field is given.
     */
    @NonNull
    public static String[] splitTrailingField(@NonNull String spec) {
        String body = spec;
        String mountSuffix = "";
        int at = spec.lastIndexOf('@');
        if (at >= 0) {
            body = spec.substring(0, at);
            mountSuffix = spec.substring(at);
        }
        int slash = body.lastIndexOf('/');
        if (slash <= 0 || slash == body.length() - 1) {
            throw new IllegalArgumentException("Cannot tell which field to read from '" + spec
                    + "'. Either pass field: '...', or use GitLab's one-line form where the last path"
                    + " segment is the field, e.g. 'production/db/password@ops'.");
        }
        return new String[] {body.substring(0, slash) + mountSuffix, body.substring(slash + 1)};
    }

    private static void validateSegment(String what, String segment) {
        if (segment.isBlank()) {
            throw new IllegalArgumentException("Empty " + what + " in Vault secret reference");
        }
        if (segment.equals(".") || segment.equals("..")) {
            throw new IllegalArgumentException("Illegal " + what + " '" + segment + "' in Vault secret reference");
        }
    }

    public String mount() {
        return mount;
    }

    public String path() {
        return path;
    }

    /** API path for a KV v2 read, e.g. {@code /v1/ops/data/production/db}, with each segment URL-encoded. */
    public String apiPath() {
        StringBuilder b = new StringBuilder("/v1/").append(encode(mount)).append("/data");
        for (String segment : path.split("/")) {
            b.append('/').append(encode(segment));
        }
        return b.toString();
    }

    private static String encode(String segment) {
        return URLEncoder.encode(segment, StandardCharsets.UTF_8).replace("+", "%20");
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof KvV2Ref)) {
            return false;
        }
        KvV2Ref that = (KvV2Ref) o;
        return mount.equals(that.mount) && path.equals(that.path);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mount, path);
    }

    @Override
    public String toString() {
        return path + "@" + mount;
    }
}
