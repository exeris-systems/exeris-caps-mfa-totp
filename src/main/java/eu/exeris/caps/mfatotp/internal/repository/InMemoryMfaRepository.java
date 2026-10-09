package eu.exeris.caps.mfatotp.internal.repository;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class InMemoryMfaRepository implements MfaRepository {

    private final Map<UUID, FactorRecord> factorsBySubject = new ConcurrentHashMap<>();
    private final Map<String, RecoveryCodeRecord> recoveryCodesByHash = new ConcurrentHashMap<>();
    private final Map<String, ChallengeRecord> challengesByHash = new ConcurrentHashMap<>();

    @Override
    public Optional<FactorRecord> findFactorBySubjectId(UUID subjectId) {
        return Optional.ofNullable(factorsBySubject.get(subjectId));
    }

    @Override
    public void saveFactor(FactorRecord record) {
        factorsBySubject.put(record.subjectId(), record);
    }

    @Override
    public void deleteFactor(UUID subjectId) {
        factorsBySubject.remove(subjectId);
    }

    @Override
    public synchronized void saveRecoveryCodes(UUID subjectId, List<RecoveryCodeRecord> codes) {
        deleteRecoveryCodes(subjectId);
        for (RecoveryCodeRecord code : codes) {
            recoveryCodesByHash.put(code.codeHash(), code);
        }
    }

    @Override
    public Optional<RecoveryCodeRecord> findRecoveryCodeByHash(String codeHash) {
        return Optional.ofNullable(recoveryCodesByHash.get(codeHash));
    }

    @Override
    public synchronized boolean consumeRecoveryCode(UUID id, Instant consumedAt) {
        for (Map.Entry<String, RecoveryCodeRecord> entry : recoveryCodesByHash.entrySet()) {
            RecoveryCodeRecord rec = entry.getValue();
            if (rec.id().equals(id)) {
                if (rec.consumedAt() != null) {
                    return false;
                }
                RecoveryCodeRecord updated = new RecoveryCodeRecord(
                        rec.id(), rec.subjectId(), rec.codeHash(), consumedAt, rec.createdAt()
                );
                entry.setValue(updated);
                return true;
            }
        }
        return false;
    }

    @Override
    public int countUnconsumedRecoveryCodes(UUID subjectId) {
        int count = 0;
        for (RecoveryCodeRecord rec : recoveryCodesByHash.values()) {
            if (rec.subjectId().equals(subjectId) && rec.consumedAt() == null) {
                count++;
            }
        }
        return count;
    }

    @Override
    public synchronized void deleteRecoveryCodes(UUID subjectId) {
        recoveryCodesByHash.values().removeIf(rec -> rec.subjectId().equals(subjectId));
    }

    @Override
    public void saveChallenge(ChallengeRecord challenge) {
        challengesByHash.put(challenge.tokenHash(), challenge);
    }

    @Override
    public Optional<ChallengeRecord> findChallengeByHash(String tokenHash) {
        return Optional.ofNullable(challengesByHash.get(tokenHash));
    }

    @Override
    public synchronized void incrementChallengeFailures(UUID challengeId) {
        for (Map.Entry<String, ChallengeRecord> entry : challengesByHash.entrySet()) {
            ChallengeRecord rec = entry.getValue();
            if (rec.id().equals(challengeId)) {
                ChallengeRecord updated = new ChallengeRecord(
                        rec.id(), rec.subjectId(), rec.tokenHash(),
                        rec.failedAttempts() + 1, rec.maxAttempts(),
                        rec.expiresAt(), rec.consumedAt(), rec.createdAt()
                );
                entry.setValue(updated);
                return;
            }
        }
    }

    @Override
    public synchronized boolean consumeChallenge(UUID challengeId, Instant consumedAt) {
        for (Map.Entry<String, ChallengeRecord> entry : challengesByHash.entrySet()) {
            ChallengeRecord rec = entry.getValue();
            if (rec.id().equals(challengeId)) {
                if (rec.consumedAt() != null) {
                    return false;
                }
                ChallengeRecord updated = new ChallengeRecord(
                        rec.id(), rec.subjectId(), rec.tokenHash(),
                        rec.failedAttempts(), rec.maxAttempts(),
                        rec.expiresAt(), consumedAt, rec.createdAt()
                );
                entry.setValue(updated);
                return true;
            }
        }
        return false;
    }
}
