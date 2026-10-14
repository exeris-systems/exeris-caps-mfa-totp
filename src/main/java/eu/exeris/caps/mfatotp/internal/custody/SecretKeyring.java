package eu.exeris.caps.mfatotp.internal.custody;

import eu.exeris.caps.mfatotp.api.exception.MfaTotpConfigurationException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The key-encryption keys that seal TOTP secrets at rest, each under an id.
 *
 * <p>The first entry is the active key and seals every new envelope; the others only open envelopes
 * sealed earlier, so a key rotates by prepending a new entry and is dropped once no stored envelope names
 * it. A key is exactly 32 random bytes (AES-256) in Base64. There is no default and no derivation from a
 * passphrase: a keyring that is absent or malformed is a configuration error, never a reason to
 * substitute a key.
 *
 * <p>Format: {@code <id>:<base64>[,<id>:<base64>...]}.
 */
public final class SecretKeyring {

    static final int KEY_LENGTH_BYTES = 32;
    private static final Pattern KEY_ID = Pattern.compile("[A-Za-z0-9._-]{1,32}");

    private final String activeId;
    private final Map<String, SecretKey> keys;

    private SecretKeyring(String activeId, Map<String, SecretKey> keys) {
        this.activeId = activeId;
        this.keys = keys;
    }

    /**
     * Parses a keyring specification. {@code source} names the configuration key in errors; the
     * specification itself never appears in a message.
     */
    public static SecretKeyring parse(String source, String specification) {
        Objects.requireNonNull(source, "source must not be null");
        if (specification == null || specification.isBlank()) {
            throw new MfaTotpConfigurationException(source, "the keyring is empty");
        }
        Map<String, SecretKey> keys = new LinkedHashMap<>();
        String activeId = null;
        String[] entries = specification.trim().split(",");
        for (int i = 0; i < entries.length; i++) {
            String entry = entries[i].trim();
            int colon = entry.indexOf(':');
            if (colon <= 0) {
                throw new MfaTotpConfigurationException(source, "entry " + (i + 1) + " is not <id>:<base64>");
            }
            String id = entry.substring(0, colon);
            if (!KEY_ID.matcher(id).matches()) {
                throw new MfaTotpConfigurationException(source, "entry " + (i + 1)
                        + " has an id that is not 1-32 characters of [A-Za-z0-9._-]");
            }
            if (keys.containsKey(id)) {
                throw new MfaTotpConfigurationException(source, "key id '" + id + "' appears twice");
            }
            byte[] material = decode(source, id, entry.substring(colon + 1).trim());
            keys.put(id, new SecretKeySpec(material, "AES"));
            Arrays.fill(material, (byte) 0);
            if (activeId == null) {
                activeId = id;
            }
        }
        return new SecretKeyring(activeId, Map.copyOf(keys));
    }

    private static byte[] decode(String source, String id, String base64) {
        byte[] decoded;
        try {
            decoded = base64.indexOf('-') >= 0 || base64.indexOf('_') >= 0
                    ? Base64.getUrlDecoder().decode(base64)
                    : Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new MfaTotpConfigurationException(source, "key '" + id + "' is not valid Base64");
        }
        if (decoded.length != KEY_LENGTH_BYTES) {
            int length = decoded.length;
            Arrays.fill(decoded, (byte) 0);
            throw new MfaTotpConfigurationException(source, "key '" + id + "' must decode to "
                    + KEY_LENGTH_BYTES + " bytes, got " + length);
        }
        return decoded;
    }

    /** Returns the id of the key that seals new envelopes. */
    public String activeId() {
        return activeId;
    }

    SecretKey activeKey() {
        return keys.get(activeId);
    }

    Optional<SecretKey> key(String id) {
        return Optional.ofNullable(keys.get(id));
    }

    @Override
    public String toString() {
        return "SecretKeyring[active=" + activeId + ", ids=" + keys.keySet() + "]";
    }
}
