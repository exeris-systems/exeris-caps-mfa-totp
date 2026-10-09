package eu.exeris.caps.mfatotp.internal;

import eu.exeris.caps.mfatotp.api.TotpVerifier;
import eu.exeris.caps.mfatotp.internal.audit.MfaAuditBridge;
import eu.exeris.caps.mfatotp.internal.crypto.Rfc6238Totp;
import eu.exeris.caps.mfatotp.internal.repository.FactorRecord;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public final class DefaultTotpVerifier implements TotpVerifier {

    private final MfaRepository repository;
    private final MfaAuditBridge auditBridge;
    private final int windowTolerance;
    private final int timeStepSeconds;
    private final int digits;

    public DefaultTotpVerifier(MfaRepository repository, MfaAuditBridge auditBridge) {
        this(repository, auditBridge, 1, 30, 6);
    }

    public DefaultTotpVerifier(
            MfaRepository repository,
            MfaAuditBridge auditBridge,
            int windowTolerance,
            int timeStepSeconds,
            int digits
    ) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.auditBridge = auditBridge;
        this.windowTolerance = windowTolerance;
        this.timeStepSeconds = timeStepSeconds;
        this.digits = digits;
    }

    @Override
    public boolean verify(UUID subjectId, String code) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Optional<FactorRecord> factorOpt = repository.findFactorBySubjectId(subjectId);
        if (factorOpt.isEmpty() || !factorOpt.get().enabled()) {
            if (auditBridge != null) {
                auditBridge.logTotpVerified(subjectId, false);
            }
            return false;
        }

        FactorRecord factor = factorOpt.get();
        boolean valid = verifyRaw(factor.secret(), code);
        if (valid) {
            FactorRecord updated = new FactorRecord(
                    factor.id(), factor.subjectId(), factor.secret(), factor.pendingSecret(),
                    factor.enabled(), factor.enrolledAt(), Instant.now(),
                    factor.createdAt(), Instant.now()
            );
            repository.saveFactor(updated);
        }
        if (auditBridge != null) {
            auditBridge.logTotpVerified(subjectId, valid);
        }
        return valid;
    }

    @Override
    public boolean verifyRaw(String base32Secret, String code) {
        return Rfc6238Totp.verifyCode(
                base32Secret,
                code,
                Instant.now().getEpochSecond(),
                timeStepSeconds,
                digits,
                windowTolerance
        );
    }
}
