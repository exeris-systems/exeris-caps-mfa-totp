package eu.exeris.caps.mfatotp.api;

import java.util.UUID;

/**
 * Service for RFC 6238 TOTP verification against enrolled subjects or raw secrets.
 */
public interface TotpVerifier {

    /**
     * Verifies a 6-digit TOTP code for an enrolled subject.
     *
     * @param subjectId the subject UUID
     * @param code      the 6-digit TOTP code
     * @return true if valid within time tolerance, false otherwise
     */
    boolean verify(UUID subjectId, String code);

    /**
     * Verifies a 6-digit TOTP code directly against a Base32 secret.
     *
     * @param base32Secret the Base32-encoded secret
     * @param code         the 6-digit TOTP code
     * @return true if valid within time tolerance, false otherwise
     */
    boolean verifyRaw(String base32Secret, String code);
}
