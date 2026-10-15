package eu.exeris.caps.mfatotp.internal.custody;

import eu.exeris.caps.mfatotp.api.exception.TotpSecretCustodyException;
import eu.exeris.caps.mfatotp.api.exception.TotpSecretCustodyException.Reason;
import eu.exeris.caps.mfatotp.internal.TestSecrets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TotpSecretEnvelopeTest {

    private final TotpSecretEnvelope envelope = TestSecrets.envelope();

    @Test
    @DisplayName("seal then open round-trips, and the envelope is neither the plaintext nor deterministic")
    void roundTrip() {
        String sealed = envelope.seal("row-1", "JBSWY3DPEHPK3PXP");

        assertThat(sealed).doesNotContain("JBSWY3DPEHPK3PXP");
        assertThat(envelope.open("row-1", sealed)).isEqualTo("JBSWY3DPEHPK3PXP");
        assertThat(envelope.seal("row-1", "JBSWY3DPEHPK3PXP")).isNotEqualTo(sealed);
        assertThat(TotpSecretEnvelope.keyIdOf(sealed)).isEqualTo("k1");
    }

    @Test
    @DisplayName("an envelope opens only for the context it was sealed for")
    void contextIsBound() {
        String sealed = envelope.seal("row-1", "SECRET");

        assertThatThrownBy(() -> envelope.open("row-2", sealed))
                .isInstanceOfSatisfying(TotpSecretCustodyException.class,
                        e -> assertThat(e.reason()).isEqualTo(Reason.AUTHENTICATION_FAILED));
    }

    @Test
    @DisplayName("a tampered envelope fails authentication")
    void tamperRefused() {
        byte[] bytes = Base64.getDecoder().decode(envelope.seal("row-1", "SECRET"));
        bytes[bytes.length - 1] ^= 1;
        String tampered = Base64.getEncoder().encodeToString(bytes);

        assertThatThrownBy(() -> envelope.open("row-1", tampered))
                .isInstanceOfSatisfying(TotpSecretCustodyException.class,
                        e -> assertThat(e.reason()).isEqualTo(Reason.AUTHENTICATION_FAILED));
    }

    @Test
    @DisplayName("plaintext, empty and garbled values are refused as not sealed, with no fallback")
    void plaintextRefused() {
        for (String stored : new String[]{"JBSWY3DPEHPK3PXP", "", "not base64 !", Base64.getEncoder().encodeToString("EXT".getBytes())}) {
            assertThatThrownBy(() -> envelope.open("row-1", stored))
                    .isInstanceOfSatisfying(TotpSecretCustodyException.class,
                            e -> assertThat(e.reason()).isEqualTo(Reason.NOT_SEALED));
        }
        assertThatThrownBy(() -> envelope.open("row-1", null)).isInstanceOf(TotpSecretCustodyException.class);
    }

    @Test
    @DisplayName("an envelope sealed under a key the keyring no longer holds is refused")
    void unknownKeyRefused() {
        String sealed = new TotpSecretEnvelope(SecretKeyring.parse("k", "other:" + TestSecrets.kekBase64(9)))
                .seal("row-1", "SECRET");

        assertThatThrownBy(() -> envelope.open("row-1", sealed))
                .isInstanceOfSatisfying(TotpSecretCustodyException.class,
                        e -> assertThat(e.reason()).isEqualTo(Reason.UNKNOWN_KEK));
    }

    @Test
    @DisplayName("after rotation the new key seals and the old key still opens")
    void rotation() {
        String old = envelope.seal("row-1", "SECRET");
        TotpSecretEnvelope rotated = new TotpSecretEnvelope(SecretKeyring.parse("k",
                "k2:" + TestSecrets.kekBase64(2) + ",k1:" + TestSecrets.kekBase64(1)));

        assertThat(rotated.open("row-1", old)).isEqualTo("SECRET");
        assertThat(TotpSecretEnvelope.keyIdOf(rotated.seal("row-1", "SECRET"))).isEqualTo("k2");
    }
}
