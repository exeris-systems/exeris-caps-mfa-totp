package eu.exeris.caps.mfatotp.internal;

import eu.exeris.caps.mfatotp.internal.crypto.Rfc6238Totp;
import eu.exeris.caps.mfatotp.internal.repository.FactorRecord;
import eu.exeris.caps.mfatotp.internal.repository.InMemoryMfaRepository;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultTotpVerifierTest {

    private static final Instant START = Instant.parse("2026-01-01T00:00:10Z");

    private MfaRepository repository;
    private MutableClock clock;
    private DefaultTotpVerifier verifier;
    private UUID subject;
    private String secret;

    @BeforeEach
    void setUp() {
        repository = new InMemoryMfaRepository();
        clock = new MutableClock(START);
        verifier = new DefaultTotpVerifier(repository, null, 1, 30, 6, clock);
        subject = UUID.randomUUID();
        secret = Rfc6238Totp.generateSecret();
        enrol(true);
    }

    private void enrol(boolean enabled) {
        repository.saveFactor(new FactorRecord(UUID.randomUUID(), subject, secret, null, enabled,
                START, null, START, START, null));
    }

    private String codeAt(Instant at) {
        return Rfc6238Totp.generateCode(secret, at.getEpochSecond(), 30, 6);
    }

    @Test
    @DisplayName("a code accepted once is refused the second time within the same window")
    void replayRefused() {
        String code = codeAt(clock.instant());

        assertThat(verifier.verify(subject, code)).isTrue();
        assertThat(verifier.verify(subject, code)).isFalse();

        clock.advance(Duration.ofSeconds(15)); // still the same step, and the code is still inside the window
        assertThat(verifier.verify(subject, code)).isFalse();
    }

    @Test
    @DisplayName("a code of an earlier step in the window is refused once a later step was accepted")
    void olderStepRefusedAfterLaterStep() {
        String previous = codeAt(clock.instant().minusSeconds(30));
        String current = codeAt(clock.instant());

        assertThat(verifier.verify(subject, current)).isTrue();
        assertThat(verifier.verify(subject, previous)).isFalse();
    }

    @Test
    @DisplayName("the code of the next step is accepted after the previous one was used")
    void nextStepAccepted() {
        String first = codeAt(clock.instant());
        assertThat(verifier.verify(subject, first)).isTrue();

        clock.advance(Duration.ofSeconds(30));
        String second = codeAt(clock.instant());
        assertThat(verifier.verify(subject, second)).isTrue();
        assertThat(verifier.verify(subject, second)).isFalse();
    }

    @Test
    @DisplayName("a wrong code does not consume the step")
    void wrongCodeDoesNotConsume() {
        String code = codeAt(clock.instant());
        String wrong = "000000".equals(code) ? "000001" : "000000";

        assertThat(verifier.verify(subject, wrong)).isFalse();
        assertThat(verifier.verify(subject, code)).isTrue();
    }

    @Test
    @DisplayName("a disabled, pending or missing factor never verifies")
    void notEnabled() {
        String code = codeAt(clock.instant());
        assertThat(verifier.verify(UUID.randomUUID(), code)).isFalse();

        UUID pendingSubject = UUID.randomUUID();
        repository.saveFactor(new FactorRecord(UUID.randomUUID(), pendingSubject, null, secret, false,
                null, null, START, START, null));
        assertThat(verifier.verify(pendingSubject, code)).isFalse();
    }

    @Test
    @DisplayName("a verification updates lastVerifiedAt and never recreates a deleted factor")
    void updatesOnlyTheExistingFactor() {
        FactorRecord before = repository.findFactorBySubjectId(subject).orElseThrow();
        String code = codeAt(clock.instant());

        assertThat(verifier.verify(subject, code)).isTrue();
        assertThat(repository.findFactorBySubjectId(subject).orElseThrow().lastVerifiedAt()).isEqualTo(clock.instant());

        repository.deleteFactor(subject);
        assertThat(repository.advanceAcceptedStep(before.id(), Long.MAX_VALUE, clock.instant())).isFalse();
        assertThat(repository.findFactorBySubjectId(subject)).isEmpty();
    }

    @Test
    @DisplayName("verifyRaw is stateless and does not consume a step")
    void verifyRawStateless() {
        String code = codeAt(clock.instant());

        assertThat(verifier.verifyRaw(secret, code)).isTrue();
        assertThat(verifier.verifyRaw(secret, code)).isTrue();
        assertThat(verifier.verify(subject, code)).isTrue();
    }

    @Test
    @DisplayName("invalid digits, step or window are refused at construction")
    void parametersValidated() {
        Clock c = Clock.systemUTC();
        assertThatThrownBy(() -> new DefaultTotpVerifier(repository, null, 1, 30, 9, c))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DefaultTotpVerifier(repository, null, 1, 30, 0, c))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DefaultTotpVerifier(repository, null, 1, 0, 6, c))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new DefaultTotpVerifier(repository, null, -1, 30, 6, c))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
