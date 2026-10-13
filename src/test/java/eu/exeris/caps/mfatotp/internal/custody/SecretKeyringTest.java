package eu.exeris.caps.mfatotp.internal.custody;

import eu.exeris.caps.mfatotp.api.exception.MfaTotpConfigurationException;
import eu.exeris.caps.mfatotp.internal.TestSecrets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretKeyringTest {

    @Test
    @DisplayName("the first entry is the active key and later entries only open")
    void firstEntryIsActive() {
        SecretKeyring ring = SecretKeyring.parse("k", "new:" + TestSecrets.kekBase64(2) + ", old:" + TestSecrets.kekBase64(1));

        assertThat(ring.activeId()).isEqualTo("new");
        assertThat(ring.key("old")).isPresent();
        assertThat(ring.key("absent")).isEmpty();
    }

    @Test
    @DisplayName("an empty, malformed, duplicated or wrong-length keyring is a configuration error that never echoes a key")
    void malformedKeyringsRefused() {
        String good = TestSecrets.kekBase64(1);
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);

        assertThatThrownBy(() -> SecretKeyring.parse("k", " ")).isInstanceOf(MfaTotpConfigurationException.class);
        assertThatThrownBy(() -> SecretKeyring.parse("k", good)).isInstanceOf(MfaTotpConfigurationException.class);
        assertThatThrownBy(() -> SecretKeyring.parse("k", "bad id:" + good)).isInstanceOf(MfaTotpConfigurationException.class);
        assertThatThrownBy(() -> SecretKeyring.parse("k", "a:" + good + ",a:" + good))
                .isInstanceOf(MfaTotpConfigurationException.class);
        assertThatThrownBy(() -> SecretKeyring.parse("k", "a:%%%")).isInstanceOf(MfaTotpConfigurationException.class);
        assertThatThrownBy(() -> SecretKeyring.parse("k", "a:" + shortKey))
                .isInstanceOf(MfaTotpConfigurationException.class)
                .hasMessageContaining("32")
                .hasMessageNotContaining(shortKey);
    }

    @Test
    @DisplayName("toString lists key ids only")
    void toStringHasNoMaterial() {
        assertThat(TestSecrets.keyring().toString()).contains("k1").doesNotContain(TestSecrets.kekBase64(1));
    }
}
