package eu.exeris.caps.mfatotp.api;

import eu.exeris.caps.mfatotp.api.exception.InvalidRecoveryCodeException;
import eu.exeris.caps.mfatotp.api.model.RecoveryCodeBatch;

import java.util.UUID;

/**
 * Service for generating, storing (hashed), verifying and consuming single-use recovery codes.
 *
 * <p>Codes carry 128 bits of entropy, but this service keeps no failure counter: bounding failed attempts is
 * the caller's obligation, through {@link MfaChallenge#recordFailure}.
 */
public interface RecoveryCodes {

    /**
     * Regenerates a fresh batch of single-use recovery codes (invalidating any existing codes).
     *
     * @param subjectId the subject UUID
     * @param count     number of recovery codes to generate (e.g. 10)
     * @return batch containing raw codes for one-time display to user
     */
    RecoveryCodeBatch regenerate(UUID subjectId, int count);

    /**
     * Verifies and immediately consumes a single-use recovery code.
     *
     * @param subjectId the subject UUID
     * @param rawCode   the raw recovery code entered by user
     * @return true if valid and consumed
     * @throws InvalidRecoveryCodeException if code is invalid or already consumed
     */
    boolean verifyAndConsume(UUID subjectId, String rawCode);

    /**
     * Returns count of remaining unconsumed recovery codes for a subject.
     *
     * @param subjectId the subject UUID
     * @return count of remaining active codes
     */
    int getRemainingCount(UUID subjectId);
}
