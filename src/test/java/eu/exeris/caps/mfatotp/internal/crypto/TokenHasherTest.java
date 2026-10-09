package eu.exeris.caps.mfatotp.internal.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TokenHasherTest {

    @Test
    @DisplayName("TokenHasher produces deterministic HMAC-SHA256 lowercase hex string with pepper")
    void testHashing() {
        String input = "test-recovery-code-123";
        String hash1 = TokenHasher.hash(input);
        String hash2 = TokenHasher.hash(input);

        assertThat(hash1).isEqualTo(hash2);
        assertThat(hash1).hasSize(64);
        assertThat(hash1).matches("^[a-f0-9]{64}$");
    }

    @Test
    @DisplayName("TokenHasher incorporates salt deterministically")
    void testSaltedHashing() {
        String input = "test-recovery-code-123";
        String saltA = "user-1";
        String saltB = "user-2";

        String hashA1 = TokenHasher.hashWithSalt(input, saltA);
        String hashA2 = TokenHasher.hashWithSalt(input, saltA);
        String hashB = TokenHasher.hashWithSalt(input, saltB);

        assertThat(hashA1).isEqualTo(hashA2);
        assertThat(hashA1).isNotEqualTo(hashB);
    }

    @Test
    @DisplayName("TokenHasher respects server pepper changes")
    void testPepperChanges() {
        String input = "code-val";
        String hashDefault = TokenHasher.hash(input);

        TokenHasher.setServerPepper("custom-pepper-key");
        String hashCustom = TokenHasher.hash(input);
        assertThat(hashCustom).isNotEqualTo(hashDefault);

        TokenHasher.setServerPepper((String) null); // reset to default
        String hashReset = TokenHasher.hash(input);
        assertThat(hashReset).isEqualTo(hashDefault);
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
