package eu.exeris.caps.mfatotp.internal.crypto;

import eu.exeris.caps.mfatotp.internal.TestSecrets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TokenHasherTest {

    private final TokenHasher hasher = TestSecrets.hasher();

    @Test
    @DisplayName("hash is a deterministic HMAC-SHA256 lowercase hex string")
    void testHashing() {
        String hash1 = hasher.hash("test-recovery-code-123");

        assertThat(hash1).isEqualTo(hasher.hash("test-recovery-code-123"));
        assertThat(hash1).matches("^[a-f0-9]{64}$");
    }

    @Test
    @DisplayName("the salt is part of the keyed input")
    void testSaltedHashing() {
        String input = "test-recovery-code-123";

        assertThat(hasher.hashWithSalt(input, "user-1")).isEqualTo(hasher.hashWithSalt(input, "user-1"));
        assertThat(hasher.hashWithSalt(input, "user-1")).isNotEqualTo(hasher.hashWithSalt(input, "user-2"));
        assertThat(hasher.hashWithSalt(input, "user-1")).isNotEqualTo(hasher.hash(input));
    }

    @Test
    @DisplayName("a different pepper yields a different digest")
    void testPepperChangesDigest() {
        byte[] other = TestSecrets.pepperBytes();
        other[0] ^= 0x55;

        assertThat(new TokenHasher(other).hash("code-val")).isNotEqualTo(hasher.hash("code-val"));
    }

    @Test
    @DisplayName("a pepper shorter than 32 bytes is refused, and there is no default")
    void testShortPepperRefused() {
        assertThatThrownBy(() -> new TokenHasher(new byte[31])).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TokenHasher(new byte[0])).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new TokenHasher(null)).isInstanceOf(NullPointerException.class);
    }

    @Test
    @DisplayName("generateSecureHex returns the requested byte length hex-encoded")
    void testSecureHex() {
        assertThat(TokenHasher.generateSecureHex(16)).hasSize(32);
        assertThat(TokenHasher.generateSecureHex(32)).hasSize(64);
    }
}
