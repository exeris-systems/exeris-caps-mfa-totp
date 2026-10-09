package eu.exeris.caps.mfatotp;

import eu.exeris.caps.mfatotp.api.MfaChallenge;
import eu.exeris.caps.mfatotp.api.RecoveryCodes;
import eu.exeris.caps.mfatotp.api.TotpFactorRegistry;
import eu.exeris.caps.mfatotp.api.TotpVerifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MfaTotpModuleTest {

    @Test
    @DisplayName("MfaTotpModule provides all 4 services and follows lifecycle hooks")
    void testModuleLifecycleAndServices() throws Exception {
        MfaTotpModule module = new MfaTotpModule();

        assertThat(module.getTotpFactorRegistry()).isNotNull();
        assertThat(module.getTotpVerifier()).isNotNull();
        assertThat(module.getRecoveryCodes()).isNotNull();
        assertThat(module.getMfaChallenge()).isNotNull();

        // Lifecycle transitions
        module.initialize();
        assertThat(module.isInitialized()).isTrue();
        module.ready();
        assertThat(module.isReady()).isTrue();

        module.drain(Duration.ofSeconds(1));
        assertThat(module.isReady()).isFalse();

        module.terminate();
        assertThat(module.isInitialized()).isFalse();
    }
}
