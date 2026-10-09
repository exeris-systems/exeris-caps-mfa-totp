package eu.exeris.caps.mfatotp.internal.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class Rfc6238TotpTest {

    @Test
    @DisplayName("RFC 6238 / RFC 4226 test vectors with HMAC-SHA1")
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
