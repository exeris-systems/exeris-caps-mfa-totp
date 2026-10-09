package eu.exeris.caps.mfatotp.api.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Challenge inspection status.
 */
public record ChallengeStatus(
        UUID challengeId,
        UUID subjectId,
        boolean consumed,
        boolean locked,
        int failedAttempts,
        int maxAttempts,
        Instant expiresAt
) {
    public ChallengeStatus {
        Objects.requireNonNull(challengeId, "challengeId must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    }
}
