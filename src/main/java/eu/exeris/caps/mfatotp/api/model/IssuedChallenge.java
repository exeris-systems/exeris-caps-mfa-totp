package eu.exeris.caps.mfatotp.api.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * An issued short-lived MFA challenge token.
 */
public record IssuedChallenge(
        UUID challengeId,
        UUID subjectId,
        String challengeToken,
        Instant expiresAt
) {
    public IssuedChallenge {
        Objects.requireNonNull(challengeId, "challengeId must not be null");
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(challengeToken, "challengeToken must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    }
}
