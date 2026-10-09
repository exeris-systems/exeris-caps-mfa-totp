package eu.exeris.caps.mfatotp.api.exception;

/**
 * Root checked exception for MFA errors.
 */
public class MfaException extends RuntimeException {
    public MfaException(String message) {
        super(message);
    }

    public MfaException(String message, Throwable cause) {
        super(message, cause);
    }
}
