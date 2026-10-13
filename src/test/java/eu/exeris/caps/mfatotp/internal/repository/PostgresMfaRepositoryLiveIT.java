package eu.exeris.caps.mfatotp.internal.repository;

import eu.exeris.caps.mfatotp.MfaTotpModule;
import eu.exeris.caps.mfatotp.api.exception.TotpSecretCustodyException;
import eu.exeris.caps.mfatotp.internal.TestSecrets;
import eu.exeris.caps.mfatotp.internal.custody.SecretKeyring;
import eu.exeris.caps.mfatotp.internal.custody.TotpSecretEnvelope;
import eu.exeris.kernel.community.persistence.jdbc.JdbcPersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link PostgresMfaRepository} against a real PostgreSQL, with the schema created from the capability's
 * own migration in a throw-away schema.
 *
 * <p>The connection comes from the environment or system properties, never from a default:
 * {@code EXERIS_TEST_PG_URL} / {@code exeris.test.pg.url} (a JDBC URL), {@code EXERIS_TEST_PG_USER} /
 * {@code exeris.test.pg.user} and {@code EXERIS_TEST_PG_PASSWORD} / {@code exeris.test.pg.password}. Without
 * all three the class is skipped.
 */
@DisplayName("PostgresMfaRepository on a live PostgreSQL")
class PostgresMfaRepositoryLiveIT {

    private static final String TEST_SCHEMA = "test_mfa_totp_live";

    private static String url;
    private static String user;
    private static String password;
    private static TransactionalExecutor tx;
    private static PostgresMfaRepository repository;

    @BeforeAll
    static void setUpDatabase() throws Exception {
        url = setting("EXERIS_TEST_PG_URL", "exeris.test.pg.url");
        user = setting("EXERIS_TEST_PG_USER", "exeris.test.pg.user");
        password = setting("EXERIS_TEST_PG_PASSWORD", "exeris.test.pg.password");
        Assumptions.assumeTrue(url != null && user != null && password != null,
                "set EXERIS_TEST_PG_URL, EXERIS_TEST_PG_USER and EXERIS_TEST_PG_PASSWORD "
                        + "(or the exeris.test.pg.* system properties) to run against PostgreSQL");

        try (Connection conn = DriverManager.getConnection(url, user, password);
             Statement stmt = conn.createStatement()) {
            stmt.execute("DROP SCHEMA IF EXISTS " + TEST_SCHEMA + " CASCADE");
            stmt.execute("CREATE SCHEMA " + TEST_SCHEMA);
        }
        try (Connection conn = open(); Statement stmt = conn.createStatement()) {
            for (String migration : MfaTotpModule.MIGRATIONS) {
                for (String statement : statements(read(migration))) {
                    stmt.execute(statement);
                }
            }
        }
        tx = new PerCallExecutor();
        repository = new PostgresMfaRepository(tx, TestSecrets.envelope());
    }

    @AfterAll
    static void dropSchema() throws SQLException {
        if (url == null || user == null || password == null) {
            return;
        }
        try (Connection conn = DriverManager.getConnection(url, user, password);
             Statement stmt = conn.createStatement()) {
            stmt.execute("DROP SCHEMA IF EXISTS " + TEST_SCHEMA + " CASCADE");
        }
    }

    private static Instant now() {
        return Instant.now().truncatedTo(ChronoUnit.MICROS);
    }

    private static FactorRecord factor(UUID subject, String secret, String pending, boolean enabled) {
        Instant now = now();
        return new FactorRecord(UUID.randomUUID(), subject, secret, pending, enabled, enabled ? now : null,
                null, now, now, null);
    }

    private static String rawColumn(UUID subject, String column) throws SQLException {
        try (Connection conn = open();
             PreparedStatement stmt = conn.prepareStatement("SELECT " + column + " FROM mfa_factors WHERE subject_id = ?")) {
            stmt.setObject(1, subject);
            try (ResultSet rs = stmt.executeQuery()) {
                assertThat(rs.next()).isTrue();
                return rs.getString(1);
            }
        }
    }

    private static void rawUpdate(UUID subject, String column, String value) throws SQLException {
        try (Connection conn = open();
             PreparedStatement stmt = conn.prepareStatement("UPDATE mfa_factors SET " + column + " = ? WHERE subject_id = ?")) {
            stmt.setString(1, value);
            stmt.setObject(2, subject);
            stmt.executeUpdate();
        }
    }

    @Test
    @DisplayName("the secret and the pending secret are stored as envelopes, never as plaintext, and read back intact")
    void secretsSealedAtRest() throws Exception {
        UUID subject = UUID.randomUUID();
        repository.saveFactor(factor(subject, "JBSWY3DPEHPK3PXP", "PENDINGSEEDPENDING", true));

        assertThat(rawColumn(subject, "secret")).doesNotContain("JBSWY3DPEHPK3PXP").startsWith("RVhU");
        assertThat(rawColumn(subject, "pending_secret")).doesNotContain("PENDINGSEEDPENDING").startsWith("RVhU");
        FactorRecord read = repository.findFactorBySubjectId(subject).orElseThrow();
        assertThat(read.secret()).isEqualTo("JBSWY3DPEHPK3PXP");
        assertThat(read.pendingSecret()).isEqualTo("PENDINGSEEDPENDING");
    }

    @Test
    @DisplayName("an absent secret is NULL in the column")
    void absentSecretIsNull() throws Exception {
        UUID subject = UUID.randomUUID();
        repository.saveFactor(factor(subject, null, "PENDINGSEEDPENDING", false));

        assertThat(rawColumn(subject, "secret")).isNull();
        assertThat(repository.findFactorBySubjectId(subject).orElseThrow().secret()).isNull();
    }

    @Test
    @DisplayName("a plaintext value planted in the column is refused, not returned")
    void plaintextRefused() throws Exception {
        UUID subject = UUID.randomUUID();
        repository.saveFactor(factor(subject, "JBSWY3DPEHPK3PXP", null, true));
        rawUpdate(subject, "secret", "JBSWY3DPEHPK3PXP");

        assertThatThrownBy(() -> repository.findFactorBySubjectId(subject))
                .isInstanceOf(TotpSecretCustodyException.class);
    }

    @Test
    @DisplayName("a sealed secret copied between rows, or between columns, fails authentication")
    void copiedSecretRefused() throws Exception {
        UUID victim = UUID.randomUUID();
        UUID attacker = UUID.randomUUID();
        repository.saveFactor(factor(victim, "VICTIMSEEDVICTIMSEED", "PENDINGSEEDPENDING", true));
        repository.saveFactor(factor(attacker, "ATTACKERSEEDATTACKER", null, true));

        rawUpdate(attacker, "secret", rawColumn(victim, "secret"));
        assertThatThrownBy(() -> repository.findFactorBySubjectId(attacker)).isInstanceOf(TotpSecretCustodyException.class);

        rawUpdate(victim, "secret", rawColumn(victim, "pending_secret"));
        assertThatThrownBy(() -> repository.findFactorBySubjectId(victim)).isInstanceOf(TotpSecretCustodyException.class);
    }

    @Test
    @DisplayName("a row sealed under a key that left the keyring is refused")
    void unknownKeyRefused() {
        UUID subject = UUID.randomUUID();
        PostgresMfaRepository other = new PostgresMfaRepository(tx,
                new TotpSecretEnvelope(SecretKeyring.parse("test", "gone:" + TestSecrets.kekBase64(5))));
        other.saveFactor(factor(subject, "JBSWY3DPEHPK3PXP", null, true));

        assertThatThrownBy(() -> repository.findFactorBySubjectId(subject)).isInstanceOf(TotpSecretCustodyException.class);
    }

    @Test
    @DisplayName("resealWithActiveKey moves every row to the active key and keeps the secrets")
    void reseal() throws Exception {
        // other tests leave rows sealed under keys this one does not hold; re-sealing aborts on them by design
        clearFactors();
        UUID subject = UUID.randomUUID();
        repository.saveFactor(factor(subject, "JBSWY3DPEHPK3PXP", "PENDINGSEEDPENDING", true));
        TotpSecretEnvelope rotated = new TotpSecretEnvelope(SecretKeyring.parse("test",
                "k2:" + TestSecrets.kekBase64(2) + ",k1:" + TestSecrets.kekBase64(1)));
        PostgresMfaRepository rotatedRepository = new PostgresMfaRepository(tx, rotated);

        assertThat(rotatedRepository.resealWithActiveKey()).isEqualTo(1);

        assertThat(TotpSecretEnvelope.keyIdOf(rawColumn(subject, "secret"))).isEqualTo("k2");
        assertThat(TotpSecretEnvelope.keyIdOf(rawColumn(subject, "pending_secret"))).isEqualTo("k2");
        PostgresMfaRepository k2Only = new PostgresMfaRepository(tx,
                new TotpSecretEnvelope(SecretKeyring.parse("test", "k2:" + TestSecrets.kekBase64(2))));
        assertThat(k2Only.findFactorBySubjectId(subject).orElseThrow().secret()).isEqualTo("JBSWY3DPEHPK3PXP");
        clearFactors();
    }

    @Test
    @DisplayName("resealWithActiveKey aborts without changing any row when one cannot be opened")
    void resealIsAllOrNothing() throws Exception {
        clearFactors();
        UUID good = UUID.randomUUID();
        UUID bad = UUID.randomUUID();
        repository.saveFactor(factor(good, "JBSWY3DPEHPK3PXP", null, true));
        repository.saveFactor(factor(bad, "OTHERSEEDOTHERSEED", null, true));
        rawUpdate(bad, "secret", "plaintext-not-an-envelope");
        String before = rawColumn(good, "secret");
        PostgresMfaRepository rotated = new PostgresMfaRepository(tx, new TotpSecretEnvelope(SecretKeyring.parse("test",
                "k2:" + TestSecrets.kekBase64(2) + ",k1:" + TestSecrets.kekBase64(1))));

        assertThatThrownBy(rotated::resealWithActiveKey).isInstanceOf(TotpSecretCustodyException.class);

        assertThat(rawColumn(good, "secret")).isEqualTo(before);
        clearFactors();
    }

    private static void clearFactors() throws SQLException {
        try (Connection conn = open(); Statement stmt = conn.createStatement()) {
            stmt.execute("DELETE FROM mfa_factors");
        }
    }

    @Test
    @DisplayName("a step is accepted once: equal and older steps are refused, a greater one is accepted")
    void acceptedStepAdvancesOnlyForward() {
        UUID subject = UUID.randomUUID();
        FactorRecord enabled = factor(subject, "JBSWY3DPEHPK3PXP", null, true);
        repository.saveFactor(enabled);

        assertThat(repository.advanceAcceptedStep(enabled.id(), 100L, now())).isTrue();
        assertThat(repository.advanceAcceptedStep(enabled.id(), 100L, now())).isFalse();
        assertThat(repository.advanceAcceptedStep(enabled.id(), 99L, now())).isFalse();
        assertThat(repository.advanceAcceptedStep(enabled.id(), 101L, now())).isTrue();

        FactorRecord read = repository.findFactorBySubjectId(subject).orElseThrow();
        assertThat(read.lastAcceptedStep()).isEqualTo(101L);
        assertThat(read.lastVerifiedAt()).isNotNull();
    }

    @Test
    @DisplayName("of many concurrent presentations of one step exactly one is accepted")
    void concurrentSameStepAdmitsOne() throws Exception {
        UUID subject = UUID.randomUUID();
        FactorRecord enabled = factor(subject, "JBSWY3DPEHPK3PXP", null, true);
        repository.saveFactor(enabled);
        int callers = 8;
        ExecutorService pool = Executors.newFixedThreadPool(callers);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<Future<Boolean>> results = new ArrayList<>();
            for (int i = 0; i < callers; i++) {
                results.add(pool.submit(() -> {
                    start.await();
                    return repository.advanceAcceptedStep(enabled.id(), 777L, now());
                }));
            }
            start.countDown();
            int accepted = 0;
            for (Future<Boolean> result : results) {
                if (result.get()) {
                    accepted++;
                }
            }
            assertThat(accepted).isEqualTo(1);
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    @DisplayName("a step is never recorded for a pending factor, and never recreates a deleted one")
    void advanceNeverInserts() {
        UUID pendingSubject = UUID.randomUUID();
        FactorRecord pending = factor(pendingSubject, null, "PENDINGSEEDPENDING", false);
        repository.saveFactor(pending);
        assertThat(repository.advanceAcceptedStep(pending.id(), 5L, now())).isFalse();

        UUID subject = UUID.randomUUID();
        FactorRecord enabled = factor(subject, "JBSWY3DPEHPK3PXP", null, true);
        repository.saveFactor(enabled);
        repository.deleteFactor(subject);
        assertThat(repository.advanceAcceptedStep(enabled.id(), 5L, now())).isFalse();
        assertThat(repository.findFactorBySubjectId(subject)).isEmpty();
    }

    private static String setting(String env, String property) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) {
            value = System.getenv(env);
        }
        return value == null || value.isBlank() ? null : value;
    }

    private static Connection open() throws SQLException {
        String separator = url.contains("?") ? "&" : "?";
        return DriverManager.getConnection(url + separator + "currentSchema=" + TEST_SCHEMA, user, password);
    }

    private static String read(String resource) throws IOException {
        try (InputStream in = PostgresMfaRepositoryLiveIT.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("missing migration " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static List<String> statements(String sql) {
        String withoutComments = sql.replaceAll("(?m)^\\s*--.*$", "");
        List<String> statements = new ArrayList<>();
        for (String candidate : withoutComments.split(";")) {
            if (!candidate.isBlank()) {
                statements.add(candidate.strip());
            }
        }
        return statements;
    }

    /** One JDBC connection per unit of work, so concurrent callers contend in the database, not in the test. */
    private static final class PerCallExecutor implements TransactionalExecutor {

        @Override
        public void execute(TransactionalWork work) {
            executeManaged(work);
        }

        @Override
        public void executeManaged(TransactionalWork work) {
            try (Connection jdbc = open()) {
                PersistenceConnection conn = new JdbcPersistenceConnection(jdbc);
                conn.beginTransaction();
                try {
                    work.run(conn);
                    conn.commit();
                } catch (RuntimeException e) {
                    conn.rollback();
                    throw e;
                }
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }

        @Override
        public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
            executeManaged(work);
        }

        @Override
        public <T> T query(Function<PersistenceConnection, T> query) {
            try (Connection jdbc = open()) {
                return query.apply(new JdbcPersistenceConnection(jdbc));
            } catch (SQLException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
