package eu.exeris.caps.mfatotp.api.exception;

public class ChallengeLockedException extends InvalidChallengeException {
    public ChallengeLockedException() {
        super("MFA challenge has been locked due to too many failed attempts");
    }
}
