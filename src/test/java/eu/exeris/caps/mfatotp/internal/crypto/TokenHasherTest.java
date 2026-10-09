package eu.exeris.caps.mfatotp.internal.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TokenHasherTest {

    @Test
    @DisplayName("TokenHasher produces deterministic SHA-256 lowercase hex string")
    void testHashing() {
        String input = "test-recovery-code-123";
        String hash1 = TokenHasher.hash(input);
        String hash2 = TokenHasher.hash(input);

        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).hasSize(64);
        assertThat(hash1).matches("^[a-f0-9]{64}$");
    }

    @Test
    @DisplayName("TokenHasher generates secure hex of requested byte length")
    void testSecureHex() {
        String token16 = TokenHasher.generateSecureHex(16);
        assertThat(token16).hasSize(32);

        String token32 = TokenHasher.generateSecureHex(32);
        assertThat(token32).hasSize(64);
    }
}
