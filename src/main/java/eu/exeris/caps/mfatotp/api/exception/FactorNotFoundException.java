package eu.exeris.caps.mfatotp.api.exception;

import java.util.UUID;

public class FactorNotFoundException extends MfaException {
    public FactorNotFoundException(UUID subjectId) {
        super("TOTP factor not found or not enabled for subject: " + subjectId);
    }
}
