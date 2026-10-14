package eu.exeris.caps.mfatotp;

import eu.exeris.caps.mfatotp.api.exception.MfaTotpConfigurationException;
import eu.exeris.caps.mfatotp.internal.TestSecrets;
import eu.exeris.caps.mfatotp.internal.config.MfaTotpSettings;
import eu.exeris.caps.mfatotp.internal.repository.InMemoryMfaRepository;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MfaTotpModuleTest {

    @Test
    @DisplayName("a wired module provides all 4 services and follows the lifecycle hooks")
    void testModuleLifecycleAndServices() throws Exception {
        MfaTotpModule module = wired();

        assertThat(module.getTotpFactorRegistry()).isNotNull();
        assertThat(module.getTotpVerifier()).isNotNull();
        assertThat(module.getRecoveryCodes()).isNotNull();
        assertThat(module.getMfaChallenge()).isNotNull();

        module.initialize();
        assertThat(module.isInitialized()).isTrue();
        module.ready();
        assertThat(module.isReady()).isTrue();

        module.drain(Duration.ofSeconds(1));
        assertThat(module.isReady()).isFalse();

        module.terminate();
        assertThat(module.isInitialized()).isFalse();
    }

    @Test
    @DisplayName("the lifecycle-only instance carries no services and does not substitute an in-memory store")
    void lifecycleOnlyInstanceRefusesServices() throws Exception {
        MfaTotpModule module = new MfaTotpModule();

        module.initialize();
        assertThat(module.isInitialized()).isTrue();
        assertThatThrownBy(module::getTotpVerifier).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(module::getTotpFactorRegistry).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(module::getRecoveryCodes).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(module::getMfaChallenge).isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("the wired constructor fails closed without a pepper, even with an executor")
    void wiredConstructorRequiresPepper() {
        assertThatThrownBy(() -> new MfaTotpModule(Map.<String, String>of(), null, null, "Exeris"))
                .isInstanceOf(MfaTotpConfigurationException.class);
        assertThatThrownBy(() -> new MfaTotpModule(Map.<String, String>of(), new NoopExecutor(), null, "Exeris"))
                .isInstanceOf(MfaTotpConfigurationException.class)
                .hasMessageContaining(MfaTotpSettings.ENV_PEPPER);
    }

    @Test
    @DisplayName("resealWithActiveKey delegates to the store and returns the number re-sealed")
    void resealDelegatesToTheStore() {
        MfaRepository inMemory = new InMemoryMfaRepository();
        MfaRepository resealing = (MfaRepository) Proxy.newProxyInstance(
                MfaRepository.class.getClassLoader(), new Class<?>[] {MfaRepository.class},
                (proxy, method, args) -> method.getName().equals("resealWithActiveKey")
                        ? 3
                        : method.invoke(inMemory, args));
        MfaTotpModule module = new MfaTotpModule(MfaTotpSettings.fromEnvironment(TestSecrets.environment()),
                resealing, null, "Exeris", Clock.systemUTC());

        assertThat(module.resealWithActiveKey()).isEqualTo(3);
    }

    @Test
    @DisplayName("resealWithActiveKey fails on the lifecycle-only instance")
    void resealRequiresWiring() {
        assertThatThrownBy(() -> new MfaTotpModule().resealWithActiveKey())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("MIGRATIONS names classpath resources that exist")
    void migrationsExist() {
        assertThat(MfaTotpModule.MIGRATIONS).isNotEmpty().allSatisfy(path ->
                assertThat(MfaTotpModule.class.getClassLoader().getResource(path)).as(path).isNotNull());
    }

    private static MfaTotpModule wired() {
        return new MfaTotpModule(MfaTotpSettings.fromEnvironment(TestSecrets.environment()),
                new InMemoryMfaRepository(), null, "Exeris", Clock.systemUTC());
    }

    private static final class NoopExecutor implements TransactionalExecutor {
        @Override public void execute(TransactionalWork work) { }
        @Override public void executeManaged(TransactionalWork work) { }
        @Override public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) { }
        @Override public <T> T query(Function<PersistenceConnection, T> query) { return null; }
    }
}
