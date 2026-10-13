package eu.exeris.caps.mfatotp.internal;

import eu.exeris.caps.mfatotp.api.TotpFactorRegistry;
import eu.exeris.caps.mfatotp.api.exception.FactorAlreadyEnrolledException;
import eu.exeris.caps.mfatotp.api.exception.FactorNotFoundException;
import eu.exeris.caps.mfatotp.api.exception.InvalidTotpCodeException;
import eu.exeris.caps.mfatotp.api.model.TotpEnrollmentSession;
import eu.exeris.caps.mfatotp.api.model.TotpFactorStatus;
import eu.exeris.caps.mfatotp.internal.crypto.Rfc6238Totp;
import eu.exeris.caps.mfatotp.internal.repository.InMemoryMfaRepository;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultTotpFactorRegistryTest {

    private MfaRepository repository;
    private DefaultTotpVerifier verifier;
    private TotpFactorRegistry registry;
    private UUID subjectId;

    @BeforeEach
    void setUp() {
        repository = new InMemoryMfaRepository();
        verifier = new DefaultTotpVerifier(repository, null);
        registry = new DefaultTotpFactorRegistry(repository, verifier, null, "Exeris");
        subjectId = UUID.randomUUID();
    }

    @Test
    @DisplayName("Complete enrollment lifecycle: begin, confirm, getStatus, disable")
    void testEnrollmentLifecycle() {
        // Initial status
        TotpFactorStatus initial = registry.getStatus(subjectId);
        assertThat(initial.enabled()).isFalse();

        // Begin enrollment
        TotpEnrollmentSession session = registry.beginEnrollment(subjectId, "alice@example.com");
        assertThat(session.subjectId()).isEqualTo(subjectId);
        assertThat(session.secret()).isNotBlank();
        assertThat(session.provisioningUri()).startsWith("otpauth://totp/Exeris:alice%40example.com?secret=" + session.secret());

        // Status before confirm is still false
        assertThat(registry.getStatus(subjectId).enabled()).isFalse();

        // Invalid code rejection
        assertThatThrownBy(() -> registry.confirmEnrollment(subjectId, "000000"))
                .isInstanceOf(InvalidTotpCodeException.class);

        // Valid code confirmation
        String validCode = Rfc6238Totp.generateCode(session.secret(), Instant.now().getEpochSecond(), 30, 6);
        TotpFactorStatus confirmed = registry.confirmEnrollment(subjectId, validCode);
        assertThat(confirmed.enabled()).isTrue();
        assertThat(confirmed.enrolledAt()).isNotNull();

        // Already enrolled error on duplicate begin
        assertThatThrownBy(() -> registry.beginEnrollment(subjectId, "alice@example.com"))
                .isInstanceOf(FactorAlreadyEnrolledException.class);

        // The code that confirmed enrolment is spent: it does not verify a second time
        assertThat(verifier.verify(subjectId, validCode)).isFalse();

        // Disable factor
        registry.disableFactor(subjectId);
        assertThat(registry.getStatus(subjectId).enabled()).isFalse();

        // Disabling again throws FactorNotFoundException
        assertThatThrownBy(() -> registry.disableFactor(subjectId))
                .isInstanceOf(FactorNotFoundException.class);
    }
}
