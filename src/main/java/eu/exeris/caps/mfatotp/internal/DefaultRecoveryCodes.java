package eu.exeris.caps.mfatotp.internal;

import eu.exeris.caps.mfatotp.api.RecoveryCodes;
import eu.exeris.caps.mfatotp.api.exception.InvalidRecoveryCodeException;
import eu.exeris.caps.mfatotp.api.model.RecoveryCodeBatch;
import eu.exeris.caps.mfatotp.internal.audit.MfaAuditBridge;
import eu.exeris.caps.mfatotp.internal.crypto.TokenHasher;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;
import eu.exeris.caps.mfatotp.internal.repository.RecoveryCodeRecord;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public final class DefaultRecoveryCodes implements RecoveryCodes {

    private final MfaRepository repository;
    private final MfaAuditBridge auditBridge;

    public DefaultRecoveryCodes(MfaRepository repository, MfaAuditBridge auditBridge) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.auditBridge = auditBridge;
    }

    @Override
    public RecoveryCodeBatch regenerate(UUID subjectId, int count) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        if (count <= 0) {
            throw new IllegalArgumentException("count must be positive");
        }

        List<String> rawCodes = new ArrayList<>(count);
        List<RecoveryCodeRecord> records = new ArrayList<>(count);
        Instant now = Instant.now();

        for (int i = 0; i < count; i++) {
            // 16 random bytes -> 32 hex chars raw code
            String rawCode = TokenHasher.generateSecureHex(16);
            String codeHash = TokenHasher.hashWithSalt(rawCode, subjectId.toString());

            rawCodes.add(rawCode);
            records.add(new RecoveryCodeRecord(
                    UUID.randomUUID(), subjectId, codeHash, null, now
            ));
        }

        repository.saveRecoveryCodes(subjectId, records);

        if (auditBridge != null) {
            auditBridge.logRecoveryCodesRegenerated(subjectId, count);
        }

        return new RecoveryCodeBatch(subjectId, rawCodes, now);
    }

    @Override
    public boolean verifyAndConsume(UUID subjectId, String rawCode) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        if (rawCode == null || rawCode.isBlank()) {
            throw new InvalidRecoveryCodeException();
        }

        String codeHash = TokenHasher.hashWithSalt(rawCode.trim(), subjectId.toString());
        Optional<RecoveryCodeRecord> recordOpt = repository.findRecoveryCodeByHash(codeHash);

        if (recordOpt.isEmpty()) {
            if (auditBridge != null) {
                auditBridge.logRecoveryCodeConsumed(subjectId, false);
            }
            throw new InvalidRecoveryCodeException();
        }

        RecoveryCodeRecord record = recordOpt.get();
        if (!record.subjectId().equals(subjectId) || record.consumedAt() != null) {
            if (auditBridge != null) {
                auditBridge.logRecoveryCodeConsumed(subjectId, false);
            }
            throw new InvalidRecoveryCodeException();
        }

        boolean consumed = repository.consumeRecoveryCode(record.id(), Instant.now());
        if (!consumed) {
            if (auditBridge != null) {
                auditBridge.logRecoveryCodeConsumed(subjectId, false);
            }
            throw new InvalidRecoveryCodeException();
        }

        if (auditBridge != null) {
            auditBridge.logRecoveryCodeConsumed(subjectId, true);
        }

        return true;
    }

    @Override
    public int getRemainingCount(UUID subjectId) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        return repository.countUnconsumedRecoveryCodes(subjectId);
    }
}
