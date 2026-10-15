package eu.exeris.caps.mfatotp.internal;

import eu.exeris.caps.mfatotp.api.RecoveryCodes;
import eu.exeris.caps.mfatotp.api.exception.InvalidRecoveryCodeException;
import eu.exeris.caps.mfatotp.api.model.RecoveryCodeBatch;
import eu.exeris.caps.mfatotp.internal.repository.InMemoryMfaRepository;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DefaultRecoveryCodesTest {

    private MfaRepository repository;
    private RecoveryCodes recoveryCodes;
    private UUID subjectId;

    @BeforeEach
    void setUp() {
        repository = new InMemoryMfaRepository();
        recoveryCodes = new DefaultRecoveryCodes(repository, TestSecrets.hasher(), null);
        subjectId = UUID.randomUUID();
    }

    @Test
    @DisplayName("Regenerate, verify and consume recovery codes single-use semantics")
    void testRecoveryCodesFlow() {
        // Regenerate batch of 10 codes
        RecoveryCodeBatch batch = recoveryCodes.regenerate(subjectId, 10);
        assertThat(batch.subjectId()).isEqualTo(subjectId);
        assertThat(batch.rawCodes()).hasSize(10);
        assertThat(recoveryCodes.getRemainingCount(subjectId)).isEqualTo(10);

        String firstCode = batch.rawCodes().get(0);

        // Consume first code
        boolean consumed = recoveryCodes.verifyAndConsume(subjectId, firstCode);
        assertThat(consumed).isTrue();
        assertThat(recoveryCodes.getRemainingCount(subjectId)).isEqualTo(9);

        // Replaying same code throws InvalidRecoveryCodeException
        assertThatThrownBy(() -> recoveryCodes.verifyAndConsume(subjectId, firstCode))
                .isInstanceOf(InvalidRecoveryCodeException.class);

        // Wrong code throws
        assertThatThrownBy(() -> recoveryCodes.verifyAndConsume(subjectId, "invalid-code-123"))
                .isInstanceOf(InvalidRecoveryCodeException.class);

        // Regenerating batch invalidates remaining old codes
        RecoveryCodeBatch secondBatch = recoveryCodes.regenerate(subjectId, 5);
        assertThat(recoveryCodes.getRemainingCount(subjectId)).isEqualTo(5);

        // Code from first batch is now invalid
        String secondCodeFromBatch1 = batch.rawCodes().get(1);
        assertThatThrownBy(() -> recoveryCodes.verifyAndConsume(subjectId, secondCodeFromBatch1))
                .isInstanceOf(InvalidRecoveryCodeException.class);

        // Code from second batch works
        assertThat(recoveryCodes.verifyAndConsume(subjectId, secondBatch.rawCodes().get(0))).isTrue();
        assertThat(recoveryCodes.getRemainingCount(subjectId)).isEqualTo(4);
    }
}
