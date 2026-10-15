package eu.exeris.caps.mfatotp.api;

import java.util.UUID;

/**
 * Service for RFC 6238 TOTP verification against enrolled subjects or raw secrets.
 *
 * <p>A time step is accepted once per factor: {@link #verify} refuses a code whose step is not greater than
 * the last accepted one, so a code that worked cannot be replayed within its window.
 *
 * <p><b>Attempt limiting is the caller's obligation.</b> This service keeps no failure counter, so a caller
 * that presents codes without bounding failures can try all 10^6 of them. Bind each verification to an
 * {@link MfaChallenge}: call {@link MfaChallenge#validate} first, {@link MfaChallenge#recordFailure} on every
 * {@code false}, and {@link MfaChallenge#consume} on success.
 */
public interface TotpVerifier {

    /**
     * Verifies a 6-digit TOTP code for an enrolled subject.
     *
     * @param subjectId the subject UUID
     * @param code      the 6-digit TOTP code
     * @return true if valid within time tolerance and not already used; false otherwise. A {@code true}
     *         consumes the code's time step.
     */
    boolean verify(UUID subjectId, String code);

    /**
     * Verifies a 6-digit TOTP code directly against a Base32 secret. Stateless: it does not consume the
     * code and applies no replay or attempt limit.
     *
     * @param base32Secret the Base32-encoded secret
     * @param code         the 6-digit TOTP code
     * @return true if valid within time tolerance, false otherwise
     */
    boolean verifyRaw(String base32Secret, String code);
}
