package eu.exeris.caps.mfatotp.internal.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Rfc6238TotpTest {

    @Test
    @DisplayName("RFC 4226 HOTP test vectors with HMAC-SHA1")
    void testHotpTestVectors() {
        // RFC 4226 test secret: "12345678901234567890" (20 bytes ASCII)
        byte[] secret = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

        String[] expectedHotp = {
                "755224", // count 0
                "287082", // count 1
                "359152", // count 2
                "969429", // count 3
                "338314", // count 4
                "254676", // count 5
                "287922", // count 6
                "162583", // count 7
                "399871", // count 8
                "520489"  // count 9
        };

        for (int i = 0; i < expectedHotp.length; i++) {
            String code = Rfc6238Totp.computeHotp(secret, i, 6);
            assertThat(code).isEqualTo(expectedHotp[i]);
        }
    }

    @Test
    @DisplayName("RFC 6238 Appendix B SHA-1 test vectors, 8 digits, 30 s step")
    void testTotpTestVectors() {
        String secret = Base32.encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII));
        long[] times = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[] expected = {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"};

        for (int i = 0; i < times.length; i++) {
            assertThat(Rfc6238Totp.generateCode(secret, times[i], 30, 8)).isEqualTo(expected[i]);
            assertThat(Rfc6238Totp.matchingCounter(secret, expected[i], times[i], 30, 8, 0))
                    .hasValue(Math.floorDiv(times[i], 30L));
        }
    }

    @Test
    @DisplayName("matchingCounter reports the step the code belongs to within the window")
    void testMatchingCounter() {
        String secret = Rfc6238Totp.generateSecret();
        long now = 1700000000L;
        String previousStepCode = Rfc6238Totp.generateCode(secret, now - 30, 30, 6);

        assertThat(Rfc6238Totp.matchingCounter(secret, previousStepCode, now, 30, 6, 1))
                .hasValue(Math.floorDiv(now, 30L) - 1);
        assertThat(Rfc6238Totp.matchingCounter(secret, previousStepCode, now, 30, 6, 0)).isEmpty();
    }

    @Test
    @DisplayName("digits outside 1..8, a non-positive step and a negative window are refused")
    void testParameterValidation() {
        String secret = Rfc6238Totp.generateSecret();

        assertThatThrownBy(() -> Rfc6238Totp.generateCode(secret, 0, 30, 9)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Rfc6238Totp.generateCode(secret, 0, 30, 0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Rfc6238Totp.generateCode(secret, 0, 0, 6)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Rfc6238Totp.verifyCode(secret, "123456", 0, 30, 6, -1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("TOTP time-step generation and window verification")
    void testTotpGenerationAndWindow() {
        String base32Secret = Rfc6238Totp.generateSecret();
        assertThat(base32Secret).isNotBlank();

        long now = 1700000000L;
        String code = Rfc6238Totp.generateCode(base32Secret, now, 30, 6);
        assertThat(code).matches("\\d{6}");

        // Exact match
        assertThat(Rfc6238Totp.verifyCode(base32Secret, code, now, 30, 6, 1)).isTrue();

        // 30s earlier (within tolerance 1)
        assertThat(Rfc6238Totp.verifyCode(base32Secret, code, now + 30, 30, 6, 1)).isTrue();

        // 30s later (within tolerance 1)
        assertThat(Rfc6238Totp.verifyCode(base32Secret, code, now - 30, 30, 6, 1)).isTrue();

        // 65s difference (outside tolerance 1)
        assertThat(Rfc6238Totp.verifyCode(base32Secret, code, now + 65, 30, 6, 1)).isFalse();
    }
}
