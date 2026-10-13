package eu.exeris.caps.mfatotp.internal;

import eu.exeris.caps.mfatotp.api.MfaChallenge;
import eu.exeris.caps.mfatotp.api.exception.ChallengeExpiredException;
import eu.exeris.caps.mfatotp.api.exception.ChallengeLockedException;
import eu.exeris.caps.mfatotp.api.exception.InvalidChallengeException;
import eu.exeris.caps.mfatotp.api.model.ChallengeStatus;
import eu.exeris.caps.mfatotp.api.model.IssuedChallenge;
import eu.exeris.caps.mfatotp.internal.audit.MfaAuditBridge;
import eu.exeris.caps.mfatotp.internal.crypto.TokenHasher;
import eu.exeris.caps.mfatotp.internal.repository.ChallengeRecord;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public final class DefaultMfaChallenge implements MfaChallenge {

    private final MfaRepository repository;
    private final TokenHasher hasher;
    private final MfaAuditBridge auditBridge;
    private final int maxFailedAttempts;

    public DefaultMfaChallenge(MfaRepository repository, TokenHasher hasher, MfaAuditBridge auditBridge) {
        this(repository, hasher, auditBridge, 5);
    }

    public DefaultMfaChallenge(
            MfaRepository repository, TokenHasher hasher, MfaAuditBridge auditBridge, int maxFailedAttempts) {
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.hasher = Objects.requireNonNull(hasher, "hasher must not be null");
        this.auditBridge = auditBridge;
        this.maxFailedAttempts = maxFailedAttempts;
    }

    @Override
    public IssuedChallenge issue(UUID subjectId, Duration ttl) {
        Objects.requireNonNull(subjectId, "subjectId must not be null");
        Duration duration = ttl != null ? ttl : Duration.ofMinutes(5);

        UUID challengeId = UUID.randomUUID();
        // 32 random bytes -> 64 hex chars opaque token
        String rawToken = TokenHasher.generateSecureHex(32);
        String tokenHash = hasher.hash(rawToken);

        Instant now = Instant.now();
        Instant expiresAt = now.plus(duration);

        ChallengeRecord record = new ChallengeRecord(
                challengeId, subjectId, tokenHash,
                0, maxFailedAttempts,
                expiresAt, null, now
        );

        repository.saveChallenge(record);

        if (auditBridge != null) {
            auditBridge.logChallengeIssued(subjectId, challengeId);
        }

        return new IssuedChallenge(challengeId, subjectId, rawToken, expiresAt);
    }

    @Override
    public ChallengeStatus validate(String rawToken) {
        ChallengeRecord record = lookupChallenge(rawToken);

        if (record.consumedAt() != null) {
            throw new InvalidChallengeException("Challenge already consumed");
        }

        if (Instant.now().isAfter(record.expiresAt())) {
            throw new ChallengeExpiredException();
        }

        if (record.failedAttempts() >= record.maxAttempts()) {
            throw new ChallengeLockedException();
        }

        return new ChallengeStatus(
                record.id(),
                record.subjectId(),
                record.consumedAt() != null,
                record.failedAttempts() >= record.maxAttempts(),
                record.failedAttempts(),
                record.maxAttempts(),
                record.expiresAt()
        );
    }

    @Override
    public void recordFailure(String rawToken) {
        ChallengeRecord record = lookupChallenge(rawToken);
        repository.incrementChallengeFailures(record.id());

        if (record.failedAttempts() + 1 >= record.maxAttempts() && auditBridge != null) {
            auditBridge.logChallengeLocked(record.subjectId(), record.id());
        }
    }

    @Override
    public UUID consume(String rawToken) {
        ChallengeRecord record = lookupChallenge(rawToken);

        validate(rawToken);

        boolean consumed = repository.consumeChallenge(record.id(), Instant.now());
        if (!consumed) {
            throw new InvalidChallengeException("Challenge could not be consumed (possible concurrent replay)");
        }

        return record.subjectId();
    }

    private ChallengeRecord lookupChallenge(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new InvalidChallengeException("Challenge token must not be blank");
        }
        String tokenHash = hasher.hash(rawToken.trim());
        return repository.findChallengeByHash(tokenHash)
                .orElseThrow(() -> new InvalidChallengeException("Challenge not found"));
    }
}
