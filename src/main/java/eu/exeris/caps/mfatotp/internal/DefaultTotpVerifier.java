package eu.exeris.caps.mfatotp.internal;

import eu.exeris.caps.mfatotp.api.TotpVerifier;
import eu.exeris.caps.mfatotp.internal.audit.MfaAuditBridge;
import eu.exeris.caps.mfatotp.internal.crypto.Rfc6238Totp;
import eu.exeris.caps.mfatotp.internal.repository.FactorRecord;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;

public final class DefaultTotpVerifier implements TotpVerifier {

    private final MfaRepository repository;
    private final MfaAuditBridge auditBridge;
    private final int windowTolerance;
    private final int timeStepSeconds;
    private final int digits;
    private final Clock clock;

    public DefaultTotpVerifier(MfaRepository repository, MfaAuditBridge auditBridge) {
        this(repository, auditBridge, 1, 30, 6, Clock.systemUTC());
    }

    /**
     * Creates a verifier with an explicit tolerance window, time step, digit count and clock.
     *
     * @throws IllegalArgumentException when the window is negative, the step is not positive, or the digits
     *                                  are not between 1 and 8
     */
    public DefaultTotpVerifier(
            MfaRepository repository,
            MfaAuditBridge auditBridge,
            int windowTolerance,
            int timeStepSeconds,
            int digits,
            Clock clock
    ) {
        Rfc6238Totp.requireParameters(timeStepSeconds, digits, windowTolerance);
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
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
        // A code is accepted once: its time step must be greater than any accepted before, and recording
        // that is a single conditional update, so concurrent presentations of one code admit one.
        OptionalLong step = matchStep(factor.secret(), code);
        boolean valid = step.isPresent()
                && repository.advanceAcceptedStep(factor.id(), step.getAsLong(), clock.instant());
        if (auditBridge != null) {
            auditBridge.logTotpVerified(subjectId, valid);
        }
        return valid;
    }

    /** Stateless: whether the code is valid now for the secret. It does not consume the code. */
    @Override
    public boolean verifyRaw(String base32Secret, String code) {
        return matchStep(base32Secret, code).isPresent();
    }

    /**
     * Finds the time step at which a code is valid, without consuming it.
     *
     * @return the time step at which {@code code} is valid for the secret now, or empty
     */
    public OptionalLong matchStep(String base32Secret, String code) {
        return Rfc6238Totp.matchingCounter(
                base32Secret,
                code,
                clock.instant().getEpochSecond(),
                timeStepSeconds,
                digits,
                windowTolerance
        );
    }
}
