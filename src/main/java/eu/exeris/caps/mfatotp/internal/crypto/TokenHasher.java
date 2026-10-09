package eu.exeris.caps.mfatotp.internal.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Objects;

/**
 * SHA-256 token hashing and secure random token generation.
 * Guarantees compliance with ADR-099 Obligation 9 (tokens and codes stored hashed).
 */
public final class TokenHasher {

    private static final SecureRandom RANDOM = new SecureRandom();

    private TokenHasher() {
    }

    /**
     * Hashes raw input string with SHA-256 and returns a 64-char lowercase hex string.
     */
    public static String hash(String raw) {
        Objects.requireNonNull(raw, "raw must not be null");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
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
