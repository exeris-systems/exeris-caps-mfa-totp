package eu.exeris.caps.mfatotp.internal.repository;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record FactorRecord(
        UUID id,
        UUID subjectId,
        String secret,
        String pendingSecret,
        boolean enabled,
        Instant enrolledAt,
        Instant lastVerifiedAt,
        Instant createdAt,
        Instant updatedAt
) {
    public FactorRecord {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
    }
}
