package eu.exeris.caps.mfatotp.internal.custody;

import eu.exeris.caps.mfatotp.api.exception.MfaException;
import eu.exeris.caps.mfatotp.api.exception.TotpSecretCustodyException;
import eu.exeris.caps.mfatotp.api.exception.TotpSecretCustodyException.Reason;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Seals and opens TOTP secrets with AES-256-GCM under a {@link SecretKeyring}.
 *
 * <p>Layout, Base64-encoded for a text column:
 * {@code "EXT" 0x01 | keyIdLength (1 byte) | keyId (ASCII) | nonce (12) | ciphertext || tag (16)}.
 * The header and the caller's context string are the associated data, so an envelope opens only under the
 * key it names and only for the row and column it was sealed for: copying one row's secret into another
 * row, or a pending secret into the active column, fails authentication. Opening never returns bytes it
 * could not authenticate, and a value that is not an envelope is refused rather than read as plaintext.
 */
public final class TotpSecretEnvelope {

    private static final byte[] MAGIC = {'E', 'X', 'T', 0x01};
    private static final int NONCE_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private final SecretKeyring keyring;
    private final SecureRandom random;

    public TotpSecretEnvelope(SecretKeyring keyring) {
        this.keyring = Objects.requireNonNull(keyring, "keyring must not be null");
        this.random = new SecureRandom();
    }

    /**
     * Seals {@code plaintext} under the active key, bound to {@code context}.
     *
     * @return the envelope as Base64 text
     */
    public String seal(String context, String plaintext) {
        Objects.requireNonNull(context, "context must not be null");
        Objects.requireNonNull(plaintext, "plaintext must not be null");
        if (plaintext.isEmpty()) {
            throw new IllegalArgumentException("plaintext must not be empty");
        }
        byte[] header = header(keyring.activeId());
        byte[] nonce = new byte[NONCE_LENGTH];
        random.nextBytes(nonce);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keyring.activeKey(), new GCMParameterSpec(TAG_LENGTH_BITS, nonce));
            cipher.updateAAD(associatedData(header, context));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            byte[] sealed = new byte[header.length + NONCE_LENGTH + ciphertext.length];
            System.arraycopy(header, 0, sealed, 0, header.length);
            System.arraycopy(nonce, 0, sealed, header.length, NONCE_LENGTH);
            System.arraycopy(ciphertext, 0, sealed, header.length + NONCE_LENGTH, ciphertext.length);
            return Base64.getEncoder().encodeToString(sealed);
        } catch (GeneralSecurityException e) {
            throw new MfaException("sealing a TOTP secret failed", e);
        }
    }

    /**
     * Opens an envelope sealed for {@code context}.
     *
     * @throws TotpSecretCustodyException when the text is not an envelope, names an unknown key, or fails
     *                                    authentication
     */
    public String open(String context, String sealedText) {
        Objects.requireNonNull(context, "context must not be null");
        byte[] sealed = decode(context, sealedText);
        int idLength = sealed[MAGIC.length] & 0xFF;
        int headerLength = MAGIC.length + 1 + idLength;
        if (idLength == 0 || sealed.length < headerLength + NONCE_LENGTH + TAG_LENGTH_BITS / 8 + 1) {
            throw new TotpSecretCustodyException(Reason.NOT_SEALED, "the secret of " + context
                    + " has a truncated envelope");
        }
        String keyId = new String(sealed, MAGIC.length + 1, idLength, StandardCharsets.US_ASCII);
        SecretKey key = keyring.key(keyId).orElseThrow(() -> new TotpSecretCustodyException(Reason.UNKNOWN_KEK,
                "the secret of " + context + " is sealed under key '" + keyId + "', which the keyring does not hold"));
        byte[] header = Arrays.copyOfRange(sealed, 0, headerLength);
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_LENGTH_BITS, sealed, headerLength, NONCE_LENGTH));
            cipher.updateAAD(associatedData(header, context));
            byte[] plain = cipher.doFinal(sealed, headerLength + NONCE_LENGTH, sealed.length - headerLength - NONCE_LENGTH);
            return new String(plain, StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            throw new TotpSecretCustodyException(Reason.AUTHENTICATION_FAILED, "the secret of " + context
                    + " failed authentication under key '" + keyId + "'", e);
        } catch (GeneralSecurityException e) {
            throw new TotpSecretCustodyException(Reason.AUTHENTICATION_FAILED, "the secret of " + context
                    + " could not be opened under key '" + keyId + "'", e);
        }
    }

    /** @return the id of the key that seals new envelopes */
    public String activeKeyId() {
        return keyring.activeId();
    }

    /** @return the key id an envelope names, or {@code null} when the text is not an envelope */
    public static String keyIdOf(String sealedText) {
        byte[] sealed = decodeOrNull(sealedText);
        if (sealed == null) {
            return null;
        }
        int idLength = sealed[MAGIC.length] & 0xFF;
        if (sealed.length < MAGIC.length + 1 + idLength) {
            return null;
        }
        return new String(sealed, MAGIC.length + 1, idLength, StandardCharsets.US_ASCII);
    }

    private static byte[] decode(String context, String sealedText) {
        byte[] sealed = decodeOrNull(sealedText);
        if (sealed == null) {
            throw new TotpSecretCustodyException(Reason.NOT_SEALED, "the secret of " + context
                    + " is not a sealed envelope; plaintext secrets are refused");
        }
        return sealed;
    }

    private static byte[] decodeOrNull(String sealedText) {
        if (sealedText == null || sealedText.isEmpty()) {
            return null;
        }
        byte[] sealed;
        try {
            sealed = Base64.getDecoder().decode(sealedText);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (sealed.length < MAGIC.length + 1 || !Arrays.equals(sealed, 0, MAGIC.length, MAGIC, 0, MAGIC.length)) {
            return null;
        }
        return sealed;
    }

    private static byte[] header(String keyId) {
        byte[] id = keyId.getBytes(StandardCharsets.US_ASCII);
        byte[] header = new byte[MAGIC.length + 1 + id.length];
        System.arraycopy(MAGIC, 0, header, 0, MAGIC.length);
        header[MAGIC.length] = (byte) id.length;
        System.arraycopy(id, 0, header, MAGIC.length + 1, id.length);
        return header;
    }

    private static byte[] associatedData(byte[] header, String context) {
        byte[] contextBytes = context.getBytes(StandardCharsets.UTF_8);
        byte[] aad = new byte[header.length + contextBytes.length];
        System.arraycopy(header, 0, aad, 0, header.length);
        System.arraycopy(contextBytes, 0, aad, header.length, contextBytes.length);
        return aad;
    }
}
