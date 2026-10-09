package eu.exeris.caps.mfatotp.api.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * TOTP factor status for a subject.
 */
public record TotpFactorStatus(
        UUID subjectId,
        boolean enabled,
        Instant enrolledAt,
        Instant lastVerifiedAt
) {
    public TotpFactorStatus {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
    }

    public static TotpFactorStatus notEnrolled(UUID subjectId) {
        return new TotpFactorStatus(subjectId, false, null, null);
    }
}
