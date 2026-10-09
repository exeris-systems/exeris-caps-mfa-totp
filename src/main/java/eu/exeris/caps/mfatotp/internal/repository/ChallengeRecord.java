package eu.exeris.caps.mfatotp.internal.repository;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record ChallengeRecord(
        UUID id,
        UUID subjectId,
        String tokenHash,
        int failedAttempts,
        int maxAttempts,
        Instant expiresAt,
        Instant consumedAt,
        Instant createdAt
) {
    public ChallengeRecord {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    }
}
