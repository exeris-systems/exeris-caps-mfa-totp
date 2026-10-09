package eu.exeris.caps.mfatotp.internal.repository;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record RecoveryCodeRecord(
        UUID id,
        UUID subjectId,
        String codeHash,
        Instant consumedAt,
        Instant createdAt
) {
    public RecoveryCodeRecord {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(codeHash, "codeHash must not be null");
    }
}
