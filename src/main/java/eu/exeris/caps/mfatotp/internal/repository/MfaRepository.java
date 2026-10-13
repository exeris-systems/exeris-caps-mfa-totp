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

    /**
     * Records {@code step} as the highest accepted time step of an enabled factor, only if it is greater
     * than the one recorded. The comparison and the update are one atomic statement, so of any number of
     * concurrent callers presenting the same step exactly one gets {@code true}, and the statement cannot
     * create a factor that was deleted meanwhile.
     *
     * @return {@code true} when the step was recorded; {@code false} when it was already used, is older
     *         than one that was, or the factor is gone or not enabled
     */
    boolean advanceAcceptedStep(UUID factorId, long step, Instant now);

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
