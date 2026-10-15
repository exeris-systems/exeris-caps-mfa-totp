package eu.exeris.caps.mfatotp.internal.repository;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * A subject's TOTP factor. {@code secret} and {@code pendingSecret} are plaintext here and sealed at rest by
 * the repository; {@code null} means absent. {@code lastAcceptedStep} is the highest time step a verification
 * has accepted, or {@code null} when none has.
 */
public record FactorRecord(
        UUID id,
        UUID subjectId,
        String secret,
        String pendingSecret,
        boolean enabled,
        Instant enrolledAt,
        Instant lastVerifiedAt,
        Instant createdAt,
        Instant updatedAt,
        Long lastAcceptedStep
) {
    public FactorRecord {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
    }
}
