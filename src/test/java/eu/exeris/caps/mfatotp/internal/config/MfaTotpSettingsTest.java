package eu.exeris.caps.mfatotp.internal.config;

import eu.exeris.caps.mfatotp.api.exception.MfaTotpConfigurationException;
import eu.exeris.caps.mfatotp.internal.TestSecrets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MfaTotpSettingsTest {

    @Test
    @DisplayName("the pepper is required: absent, blank and malformed values fail with the key named")
    void pepperRequired() {
        assertThatThrownBy(() -> MfaTotpSettings.fromEnvironment(Map.of()))
                .isInstanceOf(MfaTotpConfigurationException.class)
                .hasMessageContaining(MfaTotpSettings.ENV_PEPPER);
        assertThatThrownBy(() -> MfaTotpSettings.fromEnvironment(Map.of(MfaTotpSettings.ENV_PEPPER, "  ")))
                .isInstanceOf(MfaTotpConfigurationException.class);
        assertThatThrownBy(() -> MfaTotpSettings.fromEnvironment(Map.of(MfaTotpSettings.ENV_PEPPER, "not base64!!")))
                .isInstanceOf(MfaTotpConfigurationException.class);
    }

    @Test
    @DisplayName("a pepper under 32 bytes is refused and its value never appears in the message")
    void shortPepperRefused() {
        String shortPepper = Base64.getEncoder().encodeToString(new byte[31]);

        assertThatThrownBy(() -> MfaTotpSettings.fromEnvironment(Map.of(MfaTotpSettings.ENV_PEPPER, shortPepper)))
                .isInstanceOf(MfaTotpConfigurationException.class)
                .hasMessageContaining("32")
                .hasMessageNotContaining(shortPepper);
    }

    @Test
    @DisplayName("the pepper may come from a mounted file, but not from both sources")
    void pepperFromFile(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("pepper");
        Files.writeString(file, TestSecrets.pepperBase64() + "\n");

        Map<String, String> fromFile = Map.of(
                MfaTotpSettings.ENV_PEPPER_FILE, file.toString(), MfaTotpSettings.ENV_KEKS, TestSecrets.keyringSpec());
        MfaTotpSettings settings = MfaTotpSettings.fromEnvironment(fromFile);
        assertThat(settings.pepper()).isEqualTo(TestSecrets.pepperBytes());

        Map<String, String> both = new HashMap<>(TestSecrets.environment());
        both.put(MfaTotpSettings.ENV_PEPPER_FILE, file.toString());
        assertThatThrownBy(() -> MfaTotpSettings.fromEnvironment(both)).isInstanceOf(MfaTotpConfigurationException.class);
        assertThatThrownBy(() -> MfaTotpSettings.fromEnvironment(Map.of(
                MfaTotpSettings.ENV_PEPPER_FILE, dir.resolve("missing").toString(),
                MfaTotpSettings.ENV_KEKS, TestSecrets.keyringSpec())))
                .isInstanceOf(MfaTotpConfigurationException.class);
    }

    @Test
    @DisplayName("the key-encryption keyring is required, inline or from a file, never both")
    void keyringRequired(@TempDir Path dir) throws IOException {
        Map<String, String> pepperOnly = Map.of(MfaTotpSettings.ENV_PEPPER, TestSecrets.pepperBase64());
        assertThatThrownBy(() -> MfaTotpSettings.fromEnvironment(pepperOnly))
                .isInstanceOf(MfaTotpConfigurationException.class)
                .hasMessageContaining(MfaTotpSettings.ENV_KEKS);

        Path file = dir.resolve("keks");
        Files.writeString(file, TestSecrets.keyringSpec());
        Map<String, String> fromFile = new HashMap<>(pepperOnly);
        fromFile.put(MfaTotpSettings.ENV_KEKS_FILE, file.toString());
        assertThat(MfaTotpSettings.fromEnvironment(fromFile).keyring().activeId()).isEqualTo("k1");

        fromFile.put(MfaTotpSettings.ENV_KEKS, TestSecrets.keyringSpec());
        assertThatThrownBy(() -> MfaTotpSettings.fromEnvironment(fromFile)).isInstanceOf(MfaTotpConfigurationException.class);
    }

    @Test
    @DisplayName("challenge lifetimes default to 5 and 10 minutes, and the default may not exceed the maximum")
    void challengeLifetimes() {
        MfaTotpSettings defaults = MfaTotpSettings.fromEnvironment(TestSecrets.environment());
        assertThat(defaults.challengeTtl()).isEqualTo(Duration.ofMinutes(5));
        assertThat(defaults.challengeMaxTtl()).isEqualTo(Duration.ofMinutes(10));

        Map<String, String> env = new HashMap<>(TestSecrets.environment());
        env.put(MfaTotpSettings.ENV_CHALLENGE_TTL, "PT20M");
        assertThatThrownBy(() -> MfaTotpSettings.fromEnvironment(env)).isInstanceOf(MfaTotpConfigurationException.class);

        env.put(MfaTotpSettings.ENV_CHALLENGE_TTL, "PT-1M");
        assertThatThrownBy(() -> MfaTotpSettings.fromEnvironment(env)).isInstanceOf(MfaTotpConfigurationException.class);
    }
}
