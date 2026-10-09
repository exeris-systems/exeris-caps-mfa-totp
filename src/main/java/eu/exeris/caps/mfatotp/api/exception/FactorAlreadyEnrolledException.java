package eu.exeris.caps.mfatotp.api.exception;

import java.util.UUID;

public class FactorAlreadyEnrolledException extends MfaException {
    public FactorAlreadyEnrolledException(UUID subjectId) {
        super("TOTP factor already enrolled for subject: " + subjectId);
    }
}
