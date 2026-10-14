package eu.exeris.caps.mfatotp.internal.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Keyed hashing of recovery codes and challenge tokens: HMAC-SHA256 under a deployment-supplied
 * pepper of at least {@value #MIN_PEPPER_BYTES} bytes. A stored digest is useless
 * without the pepper, which lives outside the database; there is no built-in pepper.
 *
 * <p>{@link #hashWithSalt} prefixes the input with a caller-supplied context (the subject id)
 * and a separator, so the same raw value hashes differently per context; {@link #hash} hashes the
 * raw value alone.
 *
 * @since 0.1.0
 */
public final class TokenHasher {

    public static final int MIN_PEPPER_BYTES = 32;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final SecretKeySpec key;

    /**
     * @param pepper at least {@value #MIN_PEPPER_BYTES} bytes
     * @throws IllegalArgumentException when the pepper is shorter
     */
    public TokenHasher(byte[] pepper) {
        Objects.requireNonNull(pepper, "pepper must not be null");
        if (pepper.length < MIN_PEPPER_BYTES) {
            throw new IllegalArgumentException("pepper must be at least "
                    + MIN_PEPPER_BYTES + " bytes");
        }
        this.key = new SecretKeySpec(pepper.clone(), "HmacSHA256");
    }

    /**
     * @param raw input string; non-null
     * @return 64-character lowercase hex string
     */
    public String hash(String raw) {
        return hashWithSalt(raw, null);
    }

    /**
     * @param raw  input string; non-null
     * @param salt optional context prefix (e.g. the subject id)
     * @return 64-character lowercase hex string
     */
    public String hashWithSalt(String raw, String salt) {
        Objects.requireNonNull(raw, "raw must not be null");
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            if (salt != null && !salt.isEmpty()) {
                mac.update(salt.getBytes(StandardCharsets.UTF_8));
                mac.update((byte) ':');
            }
            return HexFormat.of().formatHex(mac.doFinal(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA256 not available", e);
        }
    }

    /**
     * Generates a cryptographically secure random token of {@code byteLength} bytes, hex-encoded.
     */
    public static String generateSecureHex(int byteLength) {
        byte[] bytes = new byte[byteLength];
        RANDOM.nextBytes(bytes);
        return HexFormat.of().formatHex(bytes);
    }
}
