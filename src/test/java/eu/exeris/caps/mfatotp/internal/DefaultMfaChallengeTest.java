package eu.exeris.caps.mfatotp.internal;

import eu.exeris.caps.mfatotp.api.MfaChallenge;
import eu.exeris.caps.mfatotp.api.exception.ChallengeExpiredException;
import eu.exeris.caps.mfatotp.api.exception.ChallengeLockedException;
import eu.exeris.caps.mfatotp.api.exception.InvalidChallengeException;
import eu.exeris.caps.mfatotp.api.model.ChallengeStatus;
import eu.exeris.caps.mfatotp.api.model.IssuedChallenge;
import eu.exeris.caps.mfatotp.internal.repository.InMemoryMfaRepository;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultMfaChallengeTest {

    private MfaRepository repository;
    private MfaChallenge mfaChallenge;
    private MutableClock clock;
    private UUID subjectId;

    @BeforeEach
    void setUp() {
        repository = new InMemoryMfaRepository();
        clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
        mfaChallenge = new DefaultMfaChallenge(repository, TestSecrets.hasher(), null, 3,
                Duration.ofMinutes(5), Duration.ofMinutes(10), clock);
        subjectId = UUID.randomUUID();
    }

    @Test
    @DisplayName("Issue challenge, validate, consume, and replay rejection")
    void testChallengeIssueAndConsume() {
        IssuedChallenge issued = mfaChallenge.issue(subjectId, Duration.ofMinutes(5));
        assertThat(issued.subjectId()).isEqualTo(subjectId);
        assertThat(issued.challengeToken()).isNotBlank();

        ChallengeStatus status = mfaChallenge.validate(issued.challengeToken());
        assertThat(status.consumed()).isFalse();
        assertThat(status.locked()).isFalse();

        UUID consumedSubject = mfaChallenge.consume(issued.challengeToken());
        assertThat(consumedSubject).isEqualTo(subjectId);

        // Replay attempt throws InvalidChallengeException
        assertThatThrownBy(() -> mfaChallenge.validate(issued.challengeToken()))
                .isInstanceOf(InvalidChallengeException.class);
        assertThatThrownBy(() -> mfaChallenge.consume(issued.challengeToken()))
                .isInstanceOf(InvalidChallengeException.class);
    }

    @Test
    @DisplayName("Challenge locking after max failed attempts")
    void testChallengeLocking() {
        IssuedChallenge issued = mfaChallenge.issue(subjectId, Duration.ofMinutes(5));

        mfaChallenge.recordFailure(issued.challengeToken());
        mfaChallenge.recordFailure(issued.challengeToken());
        assertThat(mfaChallenge.validate(issued.challengeToken()).failedAttempts()).isEqualTo(2);

        // 3rd failure locks the challenge (maxAttempts = 3)
        mfaChallenge.recordFailure(issued.challengeToken());

        assertThatThrownBy(() -> mfaChallenge.validate(issued.challengeToken()))
                .isInstanceOf(ChallengeLockedException.class);

        assertThatThrownBy(() -> mfaChallenge.consume(issued.challengeToken()))
                .isInstanceOf(ChallengeLockedException.class);
    }

    @Test
    @DisplayName("Expired challenge throws ChallengeExpiredException")
    void testChallengeExpiration() {
        IssuedChallenge issued = mfaChallenge.issue(subjectId, Duration.ofMinutes(1));
        clock.advance(Duration.ofSeconds(59));
        assertThat(mfaChallenge.validate(issued.challengeToken()).consumed()).isFalse();

        clock.advance(Duration.ofSeconds(2));
        assertThatThrownBy(() -> mfaChallenge.validate(issued.challengeToken()))
                .isInstanceOf(ChallengeExpiredException.class);
    }

    @Test
    @DisplayName("A non-positive ttl is refused and a missing one takes the default")
    void testNonPositiveTtlRefused() {
        assertThatThrownBy(() -> mfaChallenge.issue(subjectId, Duration.ZERO)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> mfaChallenge.issue(subjectId, Duration.ofMillis(-100)))
                .isInstanceOf(IllegalArgumentException.class);

        IssuedChallenge issued = mfaChallenge.issue(subjectId, null);
        assertThat(issued.expiresAt()).isEqualTo(clock.instant().plus(Duration.ofMinutes(5)));
    }

    @Test
    @DisplayName("A ttl above the configured maximum is clamped to it")
    void testTtlClampedToMaximum() {
        IssuedChallenge issued = mfaChallenge.issue(subjectId, Duration.ofDays(365));

        assertThat(issued.expiresAt()).isEqualTo(clock.instant().plus(Duration.ofMinutes(10)));
    }

    @Test
    @DisplayName("A default lifetime above the maximum, or a non-positive limit, is refused at construction")
    void testConstructionValidated() {
        assertThatThrownBy(() -> new DefaultMfaChallenge(repository, TestSecrets.hasher(), null, 3,
                Duration.ofMinutes(20), Duration.ofMinutes(10), clock)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DefaultMfaChallenge(repository, TestSecrets.hasher(), null, 0,
                Duration.ofMinutes(5), Duration.ofMinutes(10), clock)).isInstanceOf(IllegalArgumentException.class);
    }
}
