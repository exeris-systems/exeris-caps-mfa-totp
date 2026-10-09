package eu.exeris.caps.mfatotp.internal.audit;

import eu.exeris.caps.audittrail.api.AuditEvent;
import eu.exeris.caps.audittrail.api.AuditLogSink;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Optional bridge to exeris-caps-audit-trail.
 */
public final class MfaAuditBridge {

    private final AuditLogSink sink;

    public MfaAuditBridge(AuditLogSink sink) {
        this.sink = sink;
    }

    public void logFactorEnrolled(UUID subjectId) {
        emit("mfa.factor.enrolled", subjectId, Map.of("status", "enabled"));
    }

    public void logFactorDisabled(UUID subjectId) {
        emit("mfa.factor.disabled", subjectId, Map.of("status", "disabled"));
    }

    public void logTotpVerified(UUID subjectId, boolean success) {
        emit("mfa.totp.verified", subjectId, Map.of("success", success));
    }

    public void logRecoveryCodesRegenerated(UUID subjectId, int count) {
        emit("mfa.recovery_codes.regenerated", subjectId, Map.of("count", count));
    }

    public void logRecoveryCodeConsumed(UUID subjectId, boolean success) {
        emit("mfa.recovery_code.consumed", subjectId, Map.of("success", success));
    }

    public void logChallengeIssued(UUID subjectId, UUID challengeId) {
        emit("mfa.challenge.issued", subjectId, Map.of("challengeId", challengeId.toString()));
    }

    public void logChallengeLocked(UUID subjectId, UUID challengeId) {
        emit("mfa.challenge.locked", subjectId, Map.of("challengeId", challengeId.toString()));
    }

    private void emit(String action, UUID subjectId, Map<String, Object> details) {
        if (sink != null) {
            try {
                sink.emit(AuditEvent.builder()
                        .action(action)
                        .resourceType("mfa-totp")
                        .resourceId(subjectId != null ? subjectId.toString() : "")
                        .actorId(subjectId != null ? subjectId.toString() : "system")
                        .timestamp(Instant.now())
                        .details(details)
                        .build());
            } catch (Exception ignored) {
                // Audit failures must not fail security transactions
            }
        }
    }
}
