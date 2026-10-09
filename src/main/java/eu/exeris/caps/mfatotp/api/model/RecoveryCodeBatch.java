package eu.exeris.caps.mfatotp.api.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * A newly generated batch of plaintext recovery codes for a subject.
 * Displayed once to the subject; persisted as hashes only.
 */
public record RecoveryCodeBatch(
        UUID subjectId,
        List<String> rawCodes,
        Instant generatedAt
) {
    public RecoveryCodeBatch {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(rawCodes, "rawCodes must not be null");
        Objects.requireNonNull(generatedAt, "generatedAt must not be null");
        rawCodes = List.copyOf(rawCodes);
    }
}
