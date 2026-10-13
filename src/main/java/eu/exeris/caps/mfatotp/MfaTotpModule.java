package eu.exeris.caps.mfatotp;

import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.mfatotp.api.MfaChallenge;
import eu.exeris.caps.mfatotp.api.RecoveryCodes;
import eu.exeris.caps.mfatotp.api.TotpFactorRegistry;
import eu.exeris.caps.mfatotp.api.TotpVerifier;
import eu.exeris.caps.mfatotp.internal.DefaultMfaChallenge;
import eu.exeris.caps.mfatotp.internal.DefaultRecoveryCodes;
import eu.exeris.caps.mfatotp.internal.DefaultTotpFactorRegistry;
import eu.exeris.caps.mfatotp.internal.DefaultTotpVerifier;
import eu.exeris.caps.mfatotp.internal.audit.MfaAuditBridge;
import eu.exeris.caps.mfatotp.internal.repository.InMemoryMfaRepository;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;
import eu.exeris.caps.mfatotp.internal.repository.PostgresMfaRepository;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sdk.annotation.capability.CapabilityLifecycle;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;
import eu.exeris.sdk.annotation.capability.Requires;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Capability declaration and lifecycle owner for {@code exeris-caps-mfa-totp}.
 *
 * <p>Provides Layer 5 Domain Primitives:
 * <ul>
 *   <li>{@link TotpFactorRegistry} (enrol with secret and provisioning URI, confirm, disable)</li>
 *   <li>{@link TotpVerifier} (RFC 6238 verification)</li>
 *   <li>{@link RecoveryCodes} (batches of single-use codes stored hashed)</li>
 *   <li>{@link MfaChallenge} (short-lived step between password and second factor)</li>
 * </ul>
 *
 * @since 0.1.0
 */
@CapabilityModule
@CapabilityLifecycle
@Provides(service = TotpFactorRegistry.class, version = "0.1.0")
@Provides(service = TotpVerifier.class, version = "0.1.0")
@Provides(service = RecoveryCodes.class, version = "0.1.0")
@Provides(service = MfaChallenge.class, version = "0.1.0")
@Requires(service = TransactionalExecutor.class, optional = true)
@Requires(service = AuditLogSink.class, versionRange = "[0.1.0,0.2.0)", optional = true)
public final class MfaTotpModule implements CapabilityLifecycleHooks {

    private final TotpFactorRegistry totpFactorRegistry;
    private final TotpVerifier totpVerifier;
    private final RecoveryCodes recoveryCodes;
    private final MfaChallenge mfaChallenge;

    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean ready = new AtomicBoolean(false);

    /**
     * Public no-arg constructor for reflective instantiation by the composition conductor.
     */
    public MfaTotpModule() {
        this(new InMemoryMfaRepository(), null, "Exeris");
    }

    /**
     * Constructor wiring with a PostgreSQL {@link TransactionalExecutor}.
     */
    public MfaTotpModule(TransactionalExecutor tx, AuditLogSink auditLogSink) {
        this(
                tx != null ? new PostgresMfaRepository(tx) : new InMemoryMfaRepository(),
                auditLogSink != null ? new MfaAuditBridge(auditLogSink) : null,
                "Exeris"
        );
    }

    /**
     * Full constructor with explicit repository and audit bridge.
     */
    public MfaTotpModule(
            MfaRepository repository,
            MfaAuditBridge auditBridge,
            String issuer
    ) {
        Objects.requireNonNull(repository, "repository must not be null");
        this.totpVerifier = new DefaultTotpVerifier(repository, auditBridge);
        this.totpFactorRegistry = new DefaultTotpFactorRegistry(repository, this.totpVerifier, auditBridge, issuer);
        this.recoveryCodes = new DefaultRecoveryCodes(repository, auditBridge);
        this.mfaChallenge = new DefaultMfaChallenge(repository, auditBridge);
    }

    public TotpFactorRegistry getTotpFactorRegistry() {
        return totpFactorRegistry;
    }

    public TotpVerifier getTotpVerifier() {
        return totpVerifier;
    }

    public RecoveryCodes getRecoveryCodes() {
        return recoveryCodes;
    }

    public MfaChallenge getMfaChallenge() {
        return mfaChallenge;
    }

    @Override
    public void initialize() throws Exception {
        initialized.set(true);
    }

    @Override
    public void ready() throws Exception {
        ready.set(true);
    }

    @Override
    public void drain(Duration remaining) throws Exception {
        ready.set(false);
    }

    @Override
    public void terminate() {
        ready.set(false);
        initialized.set(false);
    }

    public boolean isReady() {
        return ready.get();
    }

    public boolean isInitialized() {
        return initialized.get();
    }
}
