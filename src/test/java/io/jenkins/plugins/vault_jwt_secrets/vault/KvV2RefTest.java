package io.jenkins.plugins.vault_jwt_secrets.vault;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class KvV2RefTest {

    @Test
    void parsesPathWithMount() {
        KvV2Ref ref = KvV2Ref.parse("production/db@ops", "secret");
        assertEquals("ops", ref.mount());
        assertEquals("production/db", ref.path());
        assertEquals("/v1/ops/data/production/db", ref.apiPath());
    }

    @Test
    void appliesDefaultMount() {
        KvV2Ref ref = KvV2Ref.parse("production/db", "secret");
        assertEquals("secret", ref.mount());
        assertEquals("/v1/secret/data/production/db", ref.apiPath());
    }

    @Test
    void urlEncodesSegments() {
        KvV2Ref ref = KvV2Ref.parse("team a/db#1@kv v2", "secret");
        assertEquals("/v1/kv%20v2/data/team%20a/db%231", ref.apiPath());
    }

    @Test
    void singleSegmentPath() {
        assertEquals("/v1/secret/data/db", KvV2Ref.parse("db", "secret").apiPath());
    }

    @Test
    void rejectsTraversalAndEmptySegments() {
        assertThrows(IllegalArgumentException.class, () -> KvV2Ref.parse("../etc@ops", "secret"));
        assertThrows(IllegalArgumentException.class, () -> KvV2Ref.parse("a//b@ops", "secret"));
        assertThrows(IllegalArgumentException.class, () -> KvV2Ref.parse("a/..@ops", "secret"));
        assertThrows(IllegalArgumentException.class, () -> KvV2Ref.parse("@ops", "secret"));
        assertThrows(IllegalArgumentException.class, () -> KvV2Ref.parse("a@", "secret"));
        assertThrows(IllegalArgumentException.class, () -> KvV2Ref.parse("/a@ops", "secret"));
        assertThrows(IllegalArgumentException.class, () -> KvV2Ref.parse("a/@ops", "secret"));
    }

    @Test
    void splitsGitlabTrailingFieldNotation() {
        assertArrayEquals(
                new String[] {"production/db@ops", "password"},
                KvV2Ref.splitTrailingField("production/db/password@ops"));
        assertArrayEquals(
                new String[] {"production/db", "password"}, KvV2Ref.splitTrailingField("production/db/password"));
        // no separator to split on, and no trailing field to take
        assertThrows(IllegalArgumentException.class, () -> KvV2Ref.splitTrailingField("db@ops"));
        assertThrows(IllegalArgumentException.class, () -> KvV2Ref.splitTrailingField("a/@ops"));
        assertThrows(IllegalArgumentException.class, () -> KvV2Ref.splitTrailingField(""));
    }

    @Test
    void equalityByMountAndPath() {
        assertEquals(KvV2Ref.parse("a/b@m", "secret"), KvV2Ref.parse("a/b@m", "other"));
        assertEquals("a/b@m", KvV2Ref.parse("a/b@m", "secret").toString());
    }
}
