package eu.exeris.caps.mfatotp.internal;

import eu.exeris.caps.mfatotp.internal.crypto.TokenHasher;

import java.util.Base64;
import java.util.Map;

/** Throw-away key material for tests; never a production value. */
public final class TestSecrets {

    private TestSecrets() {
    }

    public static byte[] pepperBytes() {
        byte[] bytes = new byte[TokenHasher.MIN_PEPPER_BYTES];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (i * 7 + 3);
        }
        return bytes;
    }

    public static TokenHasher hasher() {
        return new TokenHasher(pepperBytes());
    }

    public static String pepperBase64() {
        return Base64.getEncoder().encodeToString(pepperBytes());
    }

    public static Map<String, String> environment() {
        return Map.of("EXERIS_MFA_TOTP_PEPPER", pepperBase64());
    }
}
