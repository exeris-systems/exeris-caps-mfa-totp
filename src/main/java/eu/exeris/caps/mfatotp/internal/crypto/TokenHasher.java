package eu.exeris.caps.mfatotp.internal.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Token and recovery code hashing with user salt and server pepper protection (ADR-099).
 * Guarantees compliance with ADR-099 Obligation 9 (tokens and codes stored hashed) and
 * protects against offline dictionary and rainbow table attacks.
 *
 * @since 0.1.0
 */
public final class TokenHasher {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final byte[] DEFAULT_SERVER_PEPPER = "exeris-identity-recovery-server-pepper-32b!".getBytes(StandardCharsets.UTF_8);
    private static volatile byte[] serverPepper = DEFAULT_SERVER_PEPPER;

    private TokenHasher() {
    }

    /**
     * Configures the server pepper bytes injected from the host/kernel environment.
     *
     * @param pepper non-null, non-empty server pepper
     */
    public static void setServerPepper(byte[] pepper) {
        if (pepper != null && pepper.length > 0) {
            serverPepper = pepper.clone();
        } else {
            serverPepper = DEFAULT_SERVER_PEPPER;
        }
    }

    /**
     * Configures the server pepper string injected from the host/kernel environment.
     *
     * @param pepper non-null server pepper string
     */
    public static void setServerPepper(String pepper) {
        setServerPepper(pepper != null ? pepper.getBytes(StandardCharsets.UTF_8) : null);
    }

    /**
     * Hashes raw input string with HMAC-SHA256 using server pepper.
     *
     * @param raw input string; non-null
     * @return 64-character lowercase hex string
     */
    public static String hash(String raw) {
        return hashWithSalt(raw, null);
    }

    /**
     * Hashes raw input string with user salt and server pepper using HMAC-SHA256.
     *
     * @param raw  input string; non-null
     * @param salt optional user salt (e.g. subjectId string)
     * @return 64-character lowercase hex string
     */
    public static String hashWithSalt(String raw, String salt) {
        Objects.requireNonNull(raw, "raw must not be null");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(serverPepper, "HmacSHA256"));
            if (salt != null && !salt.isEmpty()) {
                mac.update(salt.getBytes(StandardCharsets.UTF_8));
                mac.update((byte) ':');
            }
            byte[] hashBytes = mac.doFinal(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 not available", e);
        }
    }

    /**
     * Generates a cryptographically secure random token string of specified byte length, hex-encoded.
     */
    public static String generateSecureHex(int byteLength) {
        byte[] bytes = new byte[byteLength];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
}
