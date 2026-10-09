package eu.exeris.caps.mfatotp.api.exception;

public class InvalidRecoveryCodeException extends MfaException {
    public InvalidRecoveryCodeException() {
        super("Invalid or already consumed recovery code");
    }
}
