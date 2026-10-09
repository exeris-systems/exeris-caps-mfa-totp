package eu.exeris.caps.mfatotp.internal.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Objects;

/**
 * Pure Java implementation of RFC 6238 (TOTP) and RFC 4226 (HOTP).
 */
public final class Rfc6238Totp {

    private static final String HMAC_SHA1 = "HmacSHA1";
    private static final int DEFAULT_TIME_STEP_SECONDS = 30;
    private static final int DEFAULT_DIGITS = 6;
    private static final int[] DIGIT_MODULO = {
            1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000
    };

    private static final SecureRandom RANDOM = new SecureRandom();

    private Rfc6238Totp() {
    }

    /**
     * Generates a 20-byte (160-bit) Base32 secret per RFC 4226 recommendation.
     */
    public static String generateSecret() {
        byte[] buffer = new byte[20];
        RANDOM.nextBytes(buffer);
        return Base32.encode(buffer);
    }

    /**
     * Computes TOTP code for a given secret at a specific epoch second timestamp.
     */
    public static String generateCode(String base32Secret, long epochSeconds, int timeStepSeconds, int digits) {
        Objects.requireNonNull(base32Secret, "base32Secret must not be null");
        byte[] key = Base32.decode(base32Secret);
        long counter = Math.floorDiv(epochSeconds, timeStepSeconds);
        return computeHotp(key, counter, digits);
    }

    /**
     * Verifies a user-supplied code against a secret at current timestamp within window tolerance.
     */
    public static boolean verifyCode(
            String base32Secret,
            String code,
            long epochSeconds,
            int timeStepSeconds,
            int digits,
            int windowTolerance
    ) {
        if (base32Secret == null || code == null) {
            return false;
        }
        String cleanCode = code.trim();
        if (cleanCode.length() != digits) {
            return false;
        }

        byte[] key;
        try {
            key = Base32.decode(base32Secret);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (key.length == 0) {
            return false;
        }

        long currentCounter = Math.floorDiv(epochSeconds, timeStepSeconds);
        for (int i = -windowTolerance; i <= windowTolerance; i++) {
            long counter = currentCounter + i;
            String expected = computeHotp(key, counter, digits);
            if (constantTimeEquals(expected, cleanCode)) {
                return true;
            }
        }
        return false;
    }

    public static String computeHotp(byte[] key, long counter, int digits) {
        try {
            byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();
            Mac mac = Mac.getInstance(HMAC_SHA1);
            mac.init(new SecretKeySpec(key, HMAC_SHA1));
            byte[] hash = mac.doFinal(counterBytes);

            // Dynamic truncation per RFC 4226 §5.4
            int offset = hash[hash.length - 1] & 0x0F;
            int binary = ((hash[offset] & 0x7F) << 24)
                    | ((hash[offset + 1] & 0xFF) << 16)
                    | ((hash[offset + 2] & 0xFF) << 8)
                    | (hash[offset + 3] & 0xFF);

            int otp = binary % DIGIT_MODULO[digits];
            return String.format("%0" + digits + "d", otp);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to calculate HMAC-SHA1", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
