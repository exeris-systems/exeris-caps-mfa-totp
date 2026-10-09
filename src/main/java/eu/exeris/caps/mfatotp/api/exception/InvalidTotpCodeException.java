package eu.exeris.caps.mfatotp.api.exception;

public class InvalidTotpCodeException extends MfaException {
    public InvalidTotpCodeException() {
        super("Invalid or expired TOTP code");
    }
}
