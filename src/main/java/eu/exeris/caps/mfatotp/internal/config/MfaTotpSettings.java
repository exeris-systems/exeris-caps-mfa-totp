package eu.exeris.caps.mfatotp.internal.config;

import eu.exeris.caps.mfatotp.api.exception.MfaTotpConfigurationException;
import eu.exeris.caps.mfatotp.internal.crypto.TokenHasher;
import eu.exeris.caps.mfatotp.internal.custody.SecretKeyring;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

/**
 * Configuration of the capability, read from environment-style settings when the module is built.
 *
 * <p>Secrets have no default and no derivation from a passphrase: an absent or malformed secret is a
 * configuration error, never a reason to substitute a value.
 */
public final class MfaTotpSettings {

    public static final String ENV_PEPPER = "EXERIS_MFA_TOTP_PEPPER";
    public static final String ENV_PEPPER_FILE = "EXERIS_MFA_TOTP_PEPPER_FILE";
    public static final String ENV_KEKS = "EXERIS_MFA_TOTP_KEKS";
    public static final String ENV_KEKS_FILE = "EXERIS_MFA_TOTP_KEKS_FILE";
    public static final String ENV_CHALLENGE_TTL = "EXERIS_MFA_TOTP_CHALLENGE_TTL";
    public static final String ENV_CHALLENGE_MAX_TTL = "EXERIS_MFA_TOTP_CHALLENGE_MAX_TTL";

    public static final Duration DEFAULT_CHALLENGE_TTL = Duration.ofMinutes(5);
    public static final Duration DEFAULT_CHALLENGE_MAX_TTL = Duration.ofMinutes(10);

    private final byte[] pepper;
    private final SecretKeyring keyring;
    private final Duration challengeTtl;
    private final Duration challengeMaxTtl;

    MfaTotpSettings(byte[] pepper, SecretKeyring keyring, Duration challengeTtl, Duration challengeMaxTtl) {
        this.pepper = pepper;
        this.keyring = keyring;
        this.challengeTtl = challengeTtl;
        this.challengeMaxTtl = challengeMaxTtl;
    }

    /**
     * Reads and validates the configuration from environment-style key/value pairs.
     *
     * @throws MfaTotpConfigurationException when a required value is absent or any value is malformed
     */
    public static MfaTotpSettings fromEnvironment(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment must not be null");
        byte[] pepper = decodePepper(secret(environment, ENV_PEPPER, ENV_PEPPER_FILE));
        SecretKeyring keyring = SecretKeyring.parse(
                environment.get(ENV_KEKS_FILE) != null && !environment.get(ENV_KEKS_FILE).isBlank() ? ENV_KEKS_FILE : ENV_KEKS,
                secret(environment, ENV_KEKS, ENV_KEKS_FILE));
        Duration ttl = duration(environment, ENV_CHALLENGE_TTL, DEFAULT_CHALLENGE_TTL);
        Duration maxTtl = duration(environment, ENV_CHALLENGE_MAX_TTL, DEFAULT_CHALLENGE_MAX_TTL);
        if (ttl.compareTo(maxTtl) > 0) {
            throw new MfaTotpConfigurationException(ENV_CHALLENGE_TTL,
                    "the default challenge lifetime exceeds " + ENV_CHALLENGE_MAX_TTL);
        }
        return new MfaTotpSettings(pepper, keyring, ttl, maxTtl);
    }

    /** Reads a secret from {@code inlineKey} or from the file named by {@code fileKey}, never both. */
    public static String secret(Map<String, String> environment, String inlineKey, String fileKey) {
        String inline = environment.get(inlineKey);
        String file = environment.get(fileKey);
        boolean hasInline = inline != null && !inline.isBlank();
        boolean hasFile = file != null && !file.isBlank();
        if (hasInline && hasFile) {
            throw new MfaTotpConfigurationException(inlineKey, "set either " + inlineKey + " or " + fileKey + ", not both");
        }
        if (hasInline) {
            return inline.trim();
        }
        if (hasFile) {
            try {
                return Files.readString(Path.of(file.trim()), StandardCharsets.UTF_8).trim();
            } catch (IOException | RuntimeException e) {
                throw new MfaTotpConfigurationException(fileKey, "the file cannot be read", e);
            }
        }
        throw new MfaTotpConfigurationException(inlineKey, "required; set " + inlineKey + " or " + fileKey);
    }

    private static byte[] decodePepper(String base64) {
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new MfaTotpConfigurationException(ENV_PEPPER, "the pepper is not valid Base64");
        }
        if (decoded.length < TokenHasher.MIN_PEPPER_BYTES) {
            int length = decoded.length;
            Arrays.fill(decoded, (byte) 0);
            throw new MfaTotpConfigurationException(ENV_PEPPER, "the pepper must decode to at least "
                    + TokenHasher.MIN_PEPPER_BYTES + " bytes, got " + length);
        }
        return decoded;
    }

    private static Duration duration(Map<String, String> environment, String key, Duration fallback) {
        String value = environment.get(key);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            Duration parsed = Duration.parse(value.trim());
            if (parsed.isZero() || parsed.isNegative()) {
                throw new MfaTotpConfigurationException(key, "must be a positive ISO-8601 duration");
            }
            return parsed;
        } catch (DateTimeParseException e) {
            throw new MfaTotpConfigurationException(key, "is not an ISO-8601 duration");
        }
    }

    /** Returns a defensive copy of the pepper bytes. */
    public byte[] pepper() {
        return pepper.clone();
    }

    /** Returns the keyring that seals TOTP secrets at rest. */
    public SecretKeyring keyring() {
        return keyring;
    }

    public Duration challengeTtl() {
        return challengeTtl;
    }

    public Duration challengeMaxTtl() {
        return challengeMaxTtl;
    }

    @Override
    public String toString() {
        return "MfaTotpSettings[challengeTtl=" + challengeTtl + ", challengeMaxTtl=" + challengeMaxTtl + "]";
    }

}
