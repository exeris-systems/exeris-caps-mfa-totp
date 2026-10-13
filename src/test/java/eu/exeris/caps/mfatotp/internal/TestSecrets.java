package eu.exeris.caps.mfatotp.internal;

import eu.exeris.caps.mfatotp.internal.crypto.TokenHasher;
import eu.exeris.caps.mfatotp.internal.custody.SecretKeyring;
import eu.exeris.caps.mfatotp.internal.custody.TotpSecretEnvelope;

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

    /** A 32-byte key whose bytes differ per {@code seed}. */
    public static String kekBase64(int seed) {
        byte[] bytes = new byte[32];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) (i * 11 + seed);
        }
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static String keyringSpec() {
        return "k1:" + kekBase64(1);
    }

    public static SecretKeyring keyring() {
        return SecretKeyring.parse("test", keyringSpec());
    }

    public static TotpSecretEnvelope envelope() {
        return new TotpSecretEnvelope(keyring());
    }

    public static Map<String, String> environment() {
        return Map.of("EXERIS_MFA_TOTP_PEPPER", pepperBase64(), "EXERIS_MFA_TOTP_KEKS", keyringSpec());
    }
}
