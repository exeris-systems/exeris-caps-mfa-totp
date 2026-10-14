package eu.exeris.caps.mfatotp;

import eu.exeris.caps.audittrail.api.AuditLogSink;
import eu.exeris.caps.mfatotp.api.MfaChallenge;
import eu.exeris.caps.mfatotp.api.RecoveryCodes;
import eu.exeris.caps.mfatotp.api.TotpFactorRegistry;
import eu.exeris.caps.mfatotp.api.TotpVerifier;
import eu.exeris.caps.mfatotp.api.exception.MfaTotpConfigurationException;
import eu.exeris.caps.mfatotp.api.exception.TotpSecretCustodyException;
import eu.exeris.caps.mfatotp.internal.DefaultMfaChallenge;
import eu.exeris.caps.mfatotp.internal.DefaultRecoveryCodes;
import eu.exeris.caps.mfatotp.internal.DefaultTotpFactorRegistry;
import eu.exeris.caps.mfatotp.internal.DefaultTotpVerifier;
import eu.exeris.caps.mfatotp.internal.audit.MfaAuditBridge;
import eu.exeris.caps.mfatotp.internal.config.MfaTotpSettings;
import eu.exeris.caps.mfatotp.internal.crypto.TokenHasher;
import eu.exeris.caps.mfatotp.internal.custody.TotpSecretEnvelope;
import eu.exeris.caps.mfatotp.internal.repository.MfaRepository;
import eu.exeris.caps.mfatotp.internal.repository.PostgresMfaRepository;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import eu.exeris.sdk.annotation.capability.CapabilityLifecycle;
import eu.exeris.sdk.annotation.capability.CapabilityModule;
import eu.exeris.sdk.annotation.capability.Provides;
import eu.exeris.sdk.annotation.capability.Requires;
import eu.exeris.sdk.composition.lifecycle.CapabilityLifecycleHooks;

import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Capability declaration and lifecycle owner for {@code exeris-caps-mfa-totp}.
 *
 * <p>Provides Layer 5 Domain Primitives:
 * <ul>
 *   <li>{@link TotpFactorRegistry} (enrol with secret and provisioning URI, confirm, disable)</li>
 *   <li>{@link TotpVerifier} (RFC 6238 verification, each time step accepted once)</li>
 *   <li>{@link RecoveryCodes} (batches of single-use codes stored hashed)</li>
 *   <li>{@link MfaChallenge} (short-lived step between password and second factor)</li>
 * </ul>
 *
 * <p>The composition conductor instantiates this class through its no-arg constructor to run the lifecycle
 * hooks, and that instance carries no services: its accessors throw {@link IllegalStateException}. The
 * composing SKU builds the wired instance with {@link #MfaTotpModule(TransactionalExecutor, AuditLogSink,
 * String)}, and applies {@link #MIGRATIONS} to the database before it does. There is no in-memory store: the
 * wired constructors read {@code EXERIS_MFA_TOTP_PEPPER} (or {@code _FILE}) from the environment and fail
 * with {@link MfaTotpConfigurationException} when the pepper is absent or shorter than 32 bytes.
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

    /**
     * The schema migrations of this capability, in the order they apply, as classpath resource paths. The
     * capability does not apply them itself; the composing SKU does, before the first service call.
     */
    public static final List<String> MIGRATIONS = List.of(
            "db/migration/exeris-caps-mfa-totp/V1__create_mfa_totp.sql");

    private final TotpFactorRegistry totpFactorRegistry;
    private final TotpVerifier totpVerifier;
    private final RecoveryCodes recoveryCodes;
    private final MfaChallenge mfaChallenge;
    private final MfaRepository repository;

    private final AtomicBoolean initialized = new AtomicBoolean(false);
    private final AtomicBoolean ready = new AtomicBoolean(false);

    /**
     * Lifecycle-only instance for reflective instantiation by the composition conductor. Its service
     * accessors throw {@link IllegalStateException}.
     */
    public MfaTotpModule() {
        this.totpFactorRegistry = null;
        this.totpVerifier = null;
        this.recoveryCodes = null;
        this.mfaChallenge = null;
        this.repository = null;
    }

    /**
     * Wired instance over PostgreSQL through the kernel Persistence SPI, configured from
     * {@code System.getenv()}.
     *
     * @param tx           kernel transactional executor; required
     * @param auditLogSink security audit sink; {@code null} when the composition carries none
     * @param issuer       issuer label of the provisioning URI; {@code null} or blank for {@code Exeris}
     * @throws MfaTotpConfigurationException when required configuration is missing or malformed
     */
    public MfaTotpModule(TransactionalExecutor tx, AuditLogSink auditLogSink, String issuer) {
        this(System.getenv(), tx, auditLogSink, issuer);
    }

    /**
     * Wired instance with an explicit configuration source.
     *
     * @param environment environment-style configuration; non-null
     * @throws MfaTotpConfigurationException when required configuration is missing or malformed
     */
    public MfaTotpModule(
            Map<String, String> environment,
            TransactionalExecutor tx,
            AuditLogSink auditLogSink,
            String issuer
    ) {
        this(MfaTotpSettings.fromEnvironment(environment), tx, auditLogSink, issuer);
    }

    private MfaTotpModule(MfaTotpSettings settings, TransactionalExecutor tx, AuditLogSink auditLogSink, String issuer) {
        this(
                settings,
                new PostgresMfaRepository(Objects.requireNonNull(tx, "tx must not be null"),
                        new TotpSecretEnvelope(settings.keyring())),
                auditLogSink != null ? new MfaAuditBridge(auditLogSink) : null,
                issuer,
                Clock.systemUTC()
        );
    }

    /** Wiring over an internal repository; package-private because its parameter types are internal. */
    MfaTotpModule(
            MfaTotpSettings settings,
            MfaRepository repository,
            MfaAuditBridge auditBridge,
            String issuer,
            Clock clock
    ) {
        Objects.requireNonNull(settings, "settings must not be null");
        Objects.requireNonNull(repository, "repository must not be null");
        Objects.requireNonNull(clock, "clock must not be null");
        this.repository = repository;
        TokenHasher hasher = new TokenHasher(settings.pepper());
        DefaultTotpVerifier verifier = new DefaultTotpVerifier(repository, auditBridge, 1, 30, 6, clock);
        this.totpVerifier = verifier;
        this.totpFactorRegistry = new DefaultTotpFactorRegistry(repository, verifier, auditBridge, issuer);
        this.recoveryCodes = new DefaultRecoveryCodes(repository, hasher, auditBridge);
        this.mfaChallenge = new DefaultMfaChallenge(repository, hasher, auditBridge, 5,
                settings.challengeTtl(), settings.challengeMaxTtl(), clock);
    }

    private static <T> T wired(T service) {
        if (service == null) {
            throw new IllegalStateException("MfaTotpModule was instantiated without its dependencies; "
                    + "the composing SKU supplies them through the wiring constructor");
        }
        return service;
    }

    /**
     * Re-seals every stored TOTP secret under the active key of the keyring, so an older key can be removed
     * from it. To rotate a key: prepend the new entry to the keyring, restart with it, call this, then
     * remove the old entry. Each secret is opened, and so authenticated, before it is sealed again; a
     * secret that cannot be opened aborts the whole unit and leaves every row unchanged.
     *
     * @return the number of factors re-sealed
     * @throws IllegalStateException    on the lifecycle-only instance, which carries no store
     * @throws TotpSecretCustodyException when a stored secret cannot be opened under the keyring
     */
    public int resealWithActiveKey() {
        return wired(repository).resealWithActiveKey();
    }

    public TotpFactorRegistry getTotpFactorRegistry() {
        return wired(totpFactorRegistry);
    }

    public TotpVerifier getTotpVerifier() {
        return wired(totpVerifier);
    }

    public RecoveryCodes getRecoveryCodes() {
        return wired(recoveryCodes);
    }

    public MfaChallenge getMfaChallenge() {
        return wired(mfaChallenge);
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
