package eu.exeris.caps.mfatotp.internal.repository;

import eu.exeris.caps.mfatotp.api.exception.TotpSecretCustodyException;
import eu.exeris.caps.mfatotp.internal.TestSecrets;
import eu.exeris.kernel.spi.persistence.PersistenceConnection;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionIsolation;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("PostgresMfaRepository Unit Tests")
class PostgresMfaRepositoryTest {

    private CapturingTransactionalExecutor tx;
    private PostgresMfaRepository repository;

    @BeforeEach
    void setUp() {
        tx = new CapturingTransactionalExecutor();
        repository = new PostgresMfaRepository(tx, TestSecrets.envelope());
    }

    @Test
    @DisplayName("saveFactor executes managed insert with correct bound parameters")
    void saveFactorExecutesManagedInsert() {
        UUID factorId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        Instant now = Instant.now();
        FactorRecord record = new FactorRecord(
                factorId, subjectId, "BASE32SECRET", "PENDINGSECRET",
                true, now, now, now, now
        );

        repository.saveFactor(record);

        assertThat(tx.executedStatements).hasSize(1);
        CapturingStatement stmt = tx.executedStatements.get(0);
        assertThat(stmt.sql).contains("INSERT INTO mfa_factors");
        assertThat(stmt.boundParameters.get(0)).isEqualTo(factorId);
        assertThat(stmt.boundParameters.get(1)).isEqualTo(subjectId);
        assertThat(stmt.boundParameters.get(2)).asString().doesNotContain("BASE32SECRET");
        assertThat(TestSecrets.envelope().open(PostgresMfaRepository.context(factorId, subjectId, "secret"),
                (String) stmt.boundParameters.get(2))).isEqualTo("BASE32SECRET");
        assertThat(TestSecrets.envelope().open(PostgresMfaRepository.context(factorId, subjectId, "pending_secret"),
                (String) stmt.boundParameters.get(3))).isEqualTo("PENDINGSECRET");
        assertThat(stmt.boundParameters.get(4)).isEqualTo(true);
        assertThat(stmt.boundParameters.get(5)).isEqualTo(now);
        assertThat(stmt.boundParameters.get(6)).isEqualTo(now);
        assertThat(stmt.boundParameters.get(7)).isEqualTo(now);
        assertThat(stmt.boundParameters.get(8)).isEqualTo(now);
    }

    @Test
    @DisplayName("findFactorBySubjectId maps row cursor fields correctly")
    void findFactorBySubjectIdMapsFields() {
        UUID factorId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        Instant now = Instant.now();

        Object[] rowData = new Object[]{
                factorId, subjectId,
                TestSecrets.envelope().seal(PostgresMfaRepository.context(factorId, subjectId, "secret"), "SECRET32"),
                TestSecrets.envelope().seal(PostgresMfaRepository.context(factorId, subjectId, "pending_secret"), "PENDING"),
                true, now, now, now, now
        };
        List<Object[]> rows = new ArrayList<>();
        rows.add(rowData);
        tx.queryResultSupplier = () -> new StubQueryResult(rows);

        Optional<FactorRecord> result = repository.findFactorBySubjectId(subjectId);

        assertThat(result).isPresent();
        FactorRecord record = result.get();
        assertThat(record.id()).isEqualTo(factorId);
        assertThat(record.subjectId()).isEqualTo(subjectId);
        assertThat(record.secret()).isEqualTo("SECRET32");
        assertThat(record.pendingSecret()).isEqualTo("PENDING");
        assertThat(record.enabled()).isTrue();
        assertThat(record.enrolledAt()).isEqualTo(now);
        assertThat(record.lastVerifiedAt()).isEqualTo(now);
    }

    @Test
    @DisplayName("a plaintext secret in a stored row is refused, never returned")
    void plaintextRowRefused() {
        UUID subjectId = UUID.randomUUID();
        Instant now = Instant.now();
        List<Object[]> rows = new ArrayList<>();
        rows.add(new Object[]{UUID.randomUUID(), subjectId, "JBSWY3DPEHPK3PXP", null, true, now, now, now, now});
        tx.queryResultSupplier = () -> new StubQueryResult(rows);

        assertThatThrownBy(() -> repository.findFactorBySubjectId(subjectId))
                .isInstanceOf(TotpSecretCustodyException.class);
    }

    @Test
    @DisplayName("a secret copied from another row fails authentication")
    void copiedSecretRefused() {
        UUID subjectId = UUID.randomUUID();
        UUID otherFactor = UUID.randomUUID();
        Instant now = Instant.now();
        String foreign = TestSecrets.envelope().seal(
                PostgresMfaRepository.context(otherFactor, subjectId, "secret"), "SECRET32");
        List<Object[]> rows = new ArrayList<>();
        rows.add(new Object[]{UUID.randomUUID(), subjectId, foreign, null, true, now, now, now, now});
        tx.queryResultSupplier = () -> new StubQueryResult(rows);

        assertThatThrownBy(() -> repository.findFactorBySubjectId(subjectId))
                .isInstanceOf(TotpSecretCustodyException.class);
    }

    @Test
    @DisplayName("an absent secret is stored as NULL, not as an empty string")
    void absentSecretIsNull() {
        UUID factorId = UUID.randomUUID();
        Instant now = Instant.now();

        repository.saveFactor(new FactorRecord(factorId, UUID.randomUUID(), null, "PENDING", false, null, null, now, now));

        CapturingStatement stmt = tx.executedStatements.get(0);
        assertThat(stmt.boundParameters).containsEntry(2, null);
        assertThat(stmt.boundParameters.get(3)).isNotNull();
    }

    @Test
    @DisplayName("saveRecoveryCodes and countUnconsumedRecoveryCodes")
    void saveAndCountRecoveryCodes() {
        UUID subjectId = UUID.randomUUID();
        UUID codeId = UUID.randomUUID();
        String hash = TestSecrets.hasher().hash("code-1");
        Instant now = Instant.now();

        RecoveryCodeRecord rec = new RecoveryCodeRecord(codeId, subjectId, hash, null, now);
        repository.saveRecoveryCodes(subjectId, List.of(rec));

        // Delete statement + insert statement
        assertThat(tx.executedStatements).hasSize(2);
        assertThat(tx.executedStatements.get(0).sql).contains("DELETE FROM mfa_recovery_codes");
        assertThat(tx.executedStatements.get(1).sql).contains("INSERT INTO mfa_recovery_codes");
        assertThat(tx.executedStatements.get(1).boundParameters.get(0)).isEqualTo(codeId);
        assertThat(tx.executedStatements.get(1).boundParameters.get(1)).isEqualTo(subjectId);
        assertThat(tx.executedStatements.get(1).boundParameters.get(2)).isEqualTo(hash);

        List<Object[]> countRows = new ArrayList<>();
        countRows.add(new Object[]{1L});
        tx.queryResultSupplier = () -> new StubQueryResult(countRows);
        int count = repository.countUnconsumedRecoveryCodes(subjectId);
        assertThat(count).isEqualTo(1);
    }

    @Test
    @DisplayName("consumeRecoveryCode executes update query and checks affected rows")
    void consumeRecoveryCodeExecutesUpdate() {
        UUID codeId = UUID.randomUUID();
        Instant now = Instant.now();

        tx.rowsAffectedResult = 1L;
        boolean consumed = repository.consumeRecoveryCode(codeId, now);
        assertThat(consumed).isTrue();

        tx.rowsAffectedResult = 0L;
        boolean consumedAgain = repository.consumeRecoveryCode(codeId, now);
        assertThat(consumedAgain).isFalse();
    }

    @Test
    @DisplayName("saveChallenge and consumeChallenge")
    void challengeLifecycleInPostgres() {
        UUID challengeId = UUID.randomUUID();
        UUID subjectId = UUID.randomUUID();
        String tokenHash = TestSecrets.hasher().hash("raw-token");
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(300);

        ChallengeRecord challenge = new ChallengeRecord(
                challengeId, subjectId, tokenHash, 0, 5, expiresAt, null, now
        );

        repository.saveChallenge(challenge);

        assertThat(tx.executedStatements).hasSize(1);
        CapturingStatement stmt = tx.executedStatements.get(0);
        assertThat(stmt.sql).contains("INSERT INTO mfa_challenges");
        assertThat(stmt.boundParameters.get(0)).isEqualTo(challengeId);
        assertThat(stmt.boundParameters.get(1)).isEqualTo(subjectId);
        assertThat(stmt.boundParameters.get(2)).isEqualTo(tokenHash);

        tx.rowsAffectedResult = 1L;
        boolean consumed = repository.consumeChallenge(challengeId, now);
        assertThat(consumed).isTrue();
    }

    // --- Stubs for TransactionalExecutor testing ---

    private static final class CapturingTransactionalExecutor implements TransactionalExecutor {
        final List<CapturingStatement> executedStatements = new ArrayList<>();
        java.util.function.Supplier<QueryResult> queryResultSupplier;
        long rowsAffectedResult = 1L;

        @Override
        public void execute(TransactionalWork work) {
            work.run(new CapturingConnection(this));
        }

        @Override
        public void executeManaged(TransactionalWork work) {
            work.run(new CapturingConnection(this));
        }

        @Override
        public void executeManaged(TransactionIsolation isolation, boolean readOnly, TransactionalWork work) {
            work.run(new CapturingConnection(this));
        }

        @Override
        public <T> T query(Function<PersistenceConnection, T> query) {
            return query.apply(new CapturingConnection(this));
        }
    }

    private static final class CapturingConnection implements PersistenceConnection {
        private final CapturingTransactionalExecutor executor;

        CapturingConnection(CapturingTransactionalExecutor executor) {
            this.executor = executor;
        }

        @Override
        public PersistenceStatement prepare(String sql) {
            CapturingStatement stmt = new CapturingStatement(sql, executor);
            executor.executedStatements.add(stmt);
            return stmt;
        }

        @Override public QueryResult executeQuery(String sql) { return null; }
        @Override public long executeUpdate(String sql) { return 0; }
        @Override public void beginTransaction() {}
        @Override public void beginTransaction(TransactionIsolation isolation, boolean readOnly) {}
        @Override public void commit() {}
        @Override public void rollback() {}
        @Override public boolean inTransaction() { return true; }
        @Override public boolean isOpen() { return true; }
        @Override public void close() {}
    }

    private static final class CapturingStatement implements PersistenceStatement {
        final String sql;
        final CapturingTransactionalExecutor executor;
        final Map<Integer, Object> boundParameters = new HashMap<>();

        CapturingStatement(String sql, CapturingTransactionalExecutor executor) {
            this.sql = sql;
            this.executor = executor;
        }

        @Override public PersistenceStatement bindInt(int index, int value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindLong(int index, long value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindShort(int index, short value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindFloat(int index, float value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindDouble(int index, double value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindBoolean(int index, boolean value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindString(int index, String value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindUuid(int index, UUID value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindBytes(int index, byte[] value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindInstant(int index, Instant value) { boundParameters.put(index, value); return this; }
        @Override public PersistenceStatement bindNull(int index) { boundParameters.put(index, null); return this; }

        @Override
        public QueryResult executeQuery() {
            if (executor.queryResultSupplier != null) {
                return executor.queryResultSupplier.get();
            }
            return new StubQueryResult(List.of());
        }

        @Override
        public long executeUpdate() {
            return executor.rowsAffectedResult;
        }

        @Override
        public void close() {}
    }

    private static final class StubQueryResult implements QueryResult {
        private final List<Object[]> rows;
        private int cursor = -1;

        StubQueryResult(List<Object[]> rows) {
            this.rows = rows;
        }

        @Override
        public boolean next() {
            cursor++;
            return cursor < rows.size();
        }

        @Override
        public RowCursor row() {
            return new StubRowCursor(rows.get(cursor));
        }

        @Override public long rowsAffected() { return rows.size(); }
        @Override public int columnCount() { return rows.isEmpty() ? 0 : rows.get(0).length; }
        @Override public String commandTag() { return "SELECT"; }
        @Override public void close() {}
    }

    private static final class StubRowCursor implements RowCursor {
        private final Object[] values;

        StubRowCursor(Object[] values) {
            this.values = values;
        }

        @Override public int getInt(int column) { return (Integer) values[column]; }
        @Override public long getLong(int column) { return (Long) values[column]; }
        @Override public short getShort(int column) { return (Short) values[column]; }
        @Override public float getFloat(int column) { return (Float) values[column]; }
        @Override public double getDouble(int column) { return (Double) values[column]; }
        @Override public boolean getBoolean(int column) { return (Boolean) values[column]; }
        @Override public boolean isNull(int column) { return values[column] == null; }
        @Override public java.lang.foreign.MemorySegment getSegment(int column) { return null; }
        @Override public int getLength(int column) { return 0; }
        @Override public String getString(int column) { return (String) values[column]; }
        @Override public byte[] getBytes(int column) { return (byte[]) values[column]; }
        @Override public UUID getUuid(int column) { return (UUID) values[column]; }
        @Override public Instant getInstant(int column) { return (Instant) values[column]; }
        @Override public int columnCount() { return values.length; }
        @Override public boolean isValid() { return true; }
    }
}
