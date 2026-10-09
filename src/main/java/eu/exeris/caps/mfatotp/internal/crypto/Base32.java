package eu.exeris.caps.mfatotp.internal.crypto;

import java.util.Arrays;

/**
 * RFC 4648 Base32 encoder and decoder without external dependencies.
 */
public final class Base32 {

    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private static final byte[] DECODE_TABLE = new byte[128];

    static {
        Arrays.fill(DECODE_TABLE, (byte) -1);
        for (int i = 0; i < ALPHABET.length(); i++) {
            DECODE_TABLE[ALPHABET.charAt(i)] = (byte) i;
            DECODE_TABLE[Character.toLowerCase(ALPHABET.charAt(i))] = (byte) i;
        }
    }

    private Base32() {
    }

    public static String encode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder out = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bitsLeft = 0;

        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                int index = (buffer >> (bitsLeft - 5)) & 0x1F;
                out.append(ALPHABET.charAt(index));
                bitsLeft -= 5;
            }
        }

        if (bitsLeft > 0) {
            int index = (buffer << (5 - bitsLeft)) & 0x1F;
            out.append(ALPHABET.charAt(index));
        }

        return out.toString();
    }

    public static byte[] decode(String encoded) {
        if (encoded == null) {
            return new byte[0];
        }
        String clean = encoded.trim().replace("=", "").replace(" ", "").replace("-", "");
        if (clean.isEmpty()) {
            return new byte[0];
        }

        int buffer = 0;
        int bitsLeft = 0;
        byte[] result = new byte[(clean.length() * 5) / 8];
        int count = 0;

        for (int i = 0; i < clean.length(); i++) {
            char c = clean.charAt(i);
            if (c >= DECODE_TABLE.length || DECODE_TABLE[c] < 0) {
                throw new IllegalArgumentException("Illegal character in Base32 string: " + c);
            }
            int val = DECODE_TABLE[c];
            buffer = (buffer << 5) | val;
            bitsLeft += 5;

            if (bitsLeft >= 8) {
                result[count++] = (byte) ((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }

        if (count == result.length) {
            return result;
        }
        return Arrays.copyOf(result, count);
    }
}
