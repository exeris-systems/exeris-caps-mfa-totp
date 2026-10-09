package eu.exeris.caps.mfatotp.api;

import eu.exeris.caps.mfatotp.api.exception.FactorAlreadyEnrolledException;
import eu.exeris.caps.mfatotp.api.exception.FactorNotFoundException;
import eu.exeris.caps.mfatotp.api.exception.InvalidTotpCodeException;
import eu.exeris.caps.mfatotp.api.model.TotpEnrollmentSession;
import eu.exeris.caps.mfatotp.api.model.TotpFactorStatus;

import java.util.UUID;

/**
 * Service for enrolling, confirming, querying, and disabling TOTP factors.
 */
public interface TotpFactorRegistry {

    /**
     * Begins enrollment for a subject, returning a pending secret and otpauth URI.
     *
     * @param subjectId    the subject UUID
     * @param accountLabel label displayed in authenticator (e.g. user email)
     * @return enrollment session with Base32 secret and provisioning URI
     * @throws FactorAlreadyEnrolledException if factor is already active
     */
    TotpEnrollmentSession beginEnrollment(UUID subjectId, String accountLabel);

    /**
     * Confirms pending enrollment with a valid TOTP code.
     *
     * @param subjectId the subject UUID
     * @param code      the 6-digit TOTP code
     * @return updated factor status
     * @throws InvalidTotpCodeException if code does not match pending secret
     */
    TotpFactorStatus confirmEnrollment(UUID subjectId, String code);

    /**
     * Disables the active TOTP factor for a subject.
     *
     * @param subjectId the subject UUID
     * @throws FactorNotFoundException if no active factor exists
     */
    void disableFactor(UUID subjectId);

    /**
     * Gets the factor status for a subject.
     *
     * @param subjectId the subject UUID
     * @return current status
     */
    TotpFactorStatus getStatus(UUID subjectId);
}
