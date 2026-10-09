package eu.exeris.caps.mfatotp.api.exception;

public class ChallengeExpiredException extends InvalidChallengeException {
    public ChallengeExpiredException() {
        super("MFA challenge has expired");
    }
}
