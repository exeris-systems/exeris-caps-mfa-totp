package eu.exeris.caps.mfatotp.api.model;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

/**
 * Result of verifying an MFA second factor.
 */
public record MfaVerificationResult(
        UUID subjectId,
        boolean success,
        FactorType factorType,
        Instant verifiedAt
) {
    public enum FactorType {
        TOTP,
        RECOVERY_CODE
    }

    public MfaVerificationResult {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Objects.requireNonNull(factorType, "factorType must not be null");
        Objects.requireNonNull(verifiedAt, "verifiedAt must not be null");
    }

    public static MfaVerificationResult success(UUID subjectId, FactorType factorType) {
        return new MfaVerificationResult(subjectId, true, factorType, Instant.now());
    }
}
