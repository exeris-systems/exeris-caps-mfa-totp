package eu.exeris.caps.mfatotp.api.exception;

public class InvalidChallengeException extends MfaException {
    public InvalidChallengeException(String message) {
        super(message);
    }
}
