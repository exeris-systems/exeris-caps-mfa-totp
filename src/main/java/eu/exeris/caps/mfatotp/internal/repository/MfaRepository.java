package eu.exeris.caps.mfatotp.internal.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface MfaRepository {

    // Factor operations
    Optional<FactorRecord> findFactorBySubjectId(UUID subjectId);
    void saveFactor(FactorRecord record);
    void deleteFactor(UUID subjectId);

    // Recovery code operations
    void saveRecoveryCodes(UUID subjectId, List<RecoveryCodeRecord> codes);
    Optional<RecoveryCodeRecord> findRecoveryCodeByHash(String codeHash);
    boolean consumeRecoveryCode(UUID id, Instant consumedAt);
    int countUnconsumedRecoveryCodes(UUID subjectId);
    void deleteRecoveryCodes(UUID subjectId);

    // Challenge operations
    void saveChallenge(ChallengeRecord challenge);
    Optional<ChallengeRecord> findChallengeByHash(String tokenHash);
    void incrementChallengeFailures(UUID challengeId);
    boolean consumeChallenge(UUID challengeId, Instant consumedAt);
}
