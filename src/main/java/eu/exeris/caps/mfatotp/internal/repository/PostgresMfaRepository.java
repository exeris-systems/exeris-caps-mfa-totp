package eu.exeris.caps.mfatotp.internal.repository;

import eu.exeris.caps.mfatotp.internal.custody.TotpSecretEnvelope;
import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public final class PostgresMfaRepository implements MfaRepository {

    private static final String COL_SECRET = "secret";
    private static final String COL_PENDING = "pending_secret";

    private final TransactionalExecutor tx;
    private final TotpSecretEnvelope envelope;

    public PostgresMfaRepository(TransactionalExecutor tx, TotpSecretEnvelope envelope) {
        this.tx = Objects.requireNonNull(tx, "TransactionalExecutor must not be null");
        this.envelope = Objects.requireNonNull(envelope, "envelope must not be null");
    }

    /**
     * The associated data of a sealed column: the row, its subject and the column, so a sealed value
     * opens only where it was written.
     */
    static String context(UUID factorId, UUID subjectId, String column) {
        return "mfa_factors/" + factorId + "/" + subjectId + "/" + column;
    }

    private String sealOrNull(UUID factorId, UUID subjectId, String column, String plain) {
        return plain == null || plain.isEmpty() ? null : envelope.seal(context(factorId, subjectId, column), plain);
    }

    private String openOrNull(UUID factorId, UUID subjectId, String column, String sealed) {
        return sealed == null ? null : envelope.open(context(factorId, subjectId, column), sealed);
    }

    @Override
    public Optional<FactorRecord> findFactorBySubjectId(UUID subjectId) {
        String sql = """
                SELECT id, subject_id, secret, pending_secret, enabled, enrolled_at, last_verified_at, created_at, updated_at, last_accepted_step
                FROM mfa_factors
                WHERE subject_id = $1
                """;
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindUuid(0, subjectId);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        UUID id = row.getUuid(0);
                        UUID subject = row.getUuid(1);
                        return Optional.of(new FactorRecord(
                                id,
                                subject,
                                openOrNull(id, subject, COL_SECRET, row.isNull(2) ? null : row.getString(2)),
                                openOrNull(id, subject, COL_PENDING, row.isNull(3) ? null : row.getString(3)),
                                row.getBoolean(4),
                                row.getInstant(5),
                                row.getInstant(6),
                                row.getInstant(7),
                                row.getInstant(8),
                                row.isNull(9) ? null : row.getLong(9)
                        ));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public void saveFactor(FactorRecord record) {
        String sql = """
                INSERT INTO mfa_factors (id, subject_id, secret, pending_secret, enabled, enrolled_at, last_verified_at, created_at, updated_at, last_accepted_step)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (subject_id) DO UPDATE SET
                    secret = EXCLUDED.secret,
                    pending_secret = EXCLUDED.pending_secret,
                    enabled = EXCLUDED.enabled,
                    enrolled_at = EXCLUDED.enrolled_at,
                    last_verified_at = EXCLUDED.last_verified_at,
                    updated_at = EXCLUDED.updated_at,
                    last_accepted_step = EXCLUDED.last_accepted_step
                """;
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindUuid(0, record.id())
                    .bindUuid(1, record.subjectId())
                    .bindBoolean(4, record.enabled());
                bindSealed(stmt, 2, sealOrNull(record.id(), record.subjectId(), COL_SECRET, record.secret()));
                bindSealed(stmt, 3, sealOrNull(record.id(), record.subjectId(), COL_PENDING, record.pendingSecret()));

                if (record.enrolledAt() != null) {
                    stmt.bindInstant(5, record.enrolledAt());
                } else {
                    stmt.bindNull(5);
                }

                if (record.lastVerifiedAt() != null) {
                    stmt.bindInstant(6, record.lastVerifiedAt());
                } else {
                    stmt.bindNull(6);
                }

                stmt.bindInstant(7, record.createdAt())
                    .bindInstant(8, record.updatedAt());

                if (record.lastAcceptedStep() != null) {
                    stmt.bindLong(9, record.lastAcceptedStep());
                } else {
                    stmt.bindNull(9);
                }

                stmt.executeUpdate();
            }
        });
    }

    @Override
    public boolean advanceAcceptedStep(UUID factorId, long step, Instant now) {
        // The step and the instant are selected once into the derived table p: each placeholder is
        // positional, so a value used twice would otherwise have to be bound twice.
        String sql = """
                UPDATE mfa_factors f
                SET last_accepted_step = p.step, last_verified_at = p.at, updated_at = p.at
                FROM (SELECT $1::bigint AS step, $2::timestamptz AS at, $3::uuid AS id) p
                WHERE f.id = p.id AND f.enabled
                  AND (f.last_accepted_step IS NULL OR f.last_accepted_step < p.step)
                """;
        AtomicLong affected = new AtomicLong();
        tx.executeManaged(conn -> {
            affected.set(0);
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindLong(0, step)
                    .bindInstant(1, now)
                    .bindUuid(2, factorId);
                affected.set(stmt.executeUpdate());
            }
        });
        return affected.get() > 0;
    }

    @Override
    public void deleteFactor(UUID subjectId) {
        String sql = "DELETE FROM mfa_factors WHERE subject_id = $1";
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindUuid(0, subjectId);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public void saveRecoveryCodes(UUID subjectId, List<RecoveryCodeRecord> codes) {
        String deleteSql = "DELETE FROM mfa_recovery_codes WHERE subject_id = $1";
        String insertSql = """
                INSERT INTO mfa_recovery_codes (id, subject_id, code_hash, consumed_at, created_at)
                VALUES ($1, $2, $3, $4, $5)
                """;
        tx.executeManaged(conn -> {
            try (PersistenceStatement delStmt = conn.prepare(deleteSql)) {
                delStmt.bindUuid(0, subjectId);
                delStmt.executeUpdate();
            }
            for (RecoveryCodeRecord code : codes) {
                try (PersistenceStatement insStmt = conn.prepare(insertSql)) {
                    insStmt.bindUuid(0, code.id())
                           .bindUuid(1, code.subjectId())
                           .bindString(2, code.codeHash());
                    if (code.consumedAt() != null) {
                        insStmt.bindInstant(3, code.consumedAt());
                    } else {
                        insStmt.bindNull(3);
                    }
                    insStmt.bindInstant(4, code.createdAt());
                    insStmt.executeUpdate();
                }
            }
        });
    }

    @Override
    public Optional<RecoveryCodeRecord> findRecoveryCodeByHash(String codeHash) {
        String sql = """
                SELECT id, subject_id, code_hash, consumed_at, created_at
                FROM mfa_recovery_codes
                WHERE code_hash = $1
                """;
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindString(0, codeHash);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        return Optional.of(new RecoveryCodeRecord(
                                row.getUuid(0),
                                row.getUuid(1),
                                row.getString(2),
                                row.getInstant(3),
                                row.getInstant(4)
                        ));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public boolean consumeRecoveryCode(UUID id, Instant consumedAt) {
        String sql = """
                UPDATE mfa_recovery_codes
                SET consumed_at = $1
                WHERE id = $2 AND consumed_at IS NULL
                """;
        // The executor may run a unit of work again on a serialization failure, so the holder is reset
        // at the start of the unit.
        AtomicLong affected = new AtomicLong();
        tx.executeManaged(conn -> {
            affected.set(0);
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindInstant(0, consumedAt)
                    .bindUuid(1, id);
                affected.set(stmt.executeUpdate());
            }
        });
        return affected.get() > 0;
    }

    @Override
    public int countUnconsumedRecoveryCodes(UUID subjectId) {
        String sql = """
                SELECT COUNT(*)
                FROM mfa_recovery_codes
                WHERE subject_id = $1 AND consumed_at IS NULL
                """;
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindUuid(0, subjectId);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        return (int) row.getLong(0);
                    }
                    return 0;
                }
            }
        });
    }

    @Override
    public void deleteRecoveryCodes(UUID subjectId) {
        String sql = "DELETE FROM mfa_recovery_codes WHERE subject_id = $1";
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindUuid(0, subjectId);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public void saveChallenge(ChallengeRecord challenge) {
        String sql = """
                INSERT INTO mfa_challenges (id, subject_id, token_hash, failed_attempts, max_attempts, expires_at, consumed_at, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """;
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindUuid(0, challenge.id())
                    .bindUuid(1, challenge.subjectId())
                    .bindString(2, challenge.tokenHash())
                    .bindInt(3, challenge.failedAttempts())
                    .bindInt(4, challenge.maxAttempts())
                    .bindInstant(5, challenge.expiresAt());
                if (challenge.consumedAt() != null) {
                    stmt.bindInstant(6, challenge.consumedAt());
                } else {
                    stmt.bindNull(6);
                }
                stmt.bindInstant(7, challenge.createdAt());
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public Optional<ChallengeRecord> findChallengeByHash(String tokenHash) {
        String sql = """
                SELECT id, subject_id, token_hash, failed_attempts, max_attempts, expires_at, consumed_at, created_at
                FROM mfa_challenges
                WHERE token_hash = $1
                """;
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindString(0, tokenHash);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        return Optional.of(new ChallengeRecord(
                                row.getUuid(0),
                                row.getUuid(1),
                                row.getString(2),
                                row.getInt(3),
                                row.getInt(4),
                                row.getInstant(5),
                                row.getInstant(6),
                                row.getInstant(7)
                        ));
                    }
                    return Optional.empty();
                }
            }
        });
    }

    @Override
    public void incrementChallengeFailures(UUID challengeId) {
        String sql = """
                UPDATE mfa_challenges
                SET failed_attempts = failed_attempts + 1
                WHERE id = $1
                """;
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindUuid(0, challengeId);
                stmt.executeUpdate();
            }
        });
    }

    @Override
    public boolean consumeChallenge(UUID challengeId, Instant consumedAt) {
        String sql = """
                UPDATE mfa_challenges
                SET consumed_at = $1
                WHERE id = $2 AND consumed_at IS NULL
                """;
        // The executor may run a unit of work again on a serialization failure, so the holder is reset
        // at the start of the unit.
        AtomicLong affected = new AtomicLong();
        tx.executeManaged(conn -> {
            affected.set(0);
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindInstant(0, consumedAt)
                    .bindUuid(1, challengeId);
                affected.set(stmt.executeUpdate());
            }
        });
        return affected.get() > 0;
    }

    /**
     * Re-seals every stored secret under the active key of the keyring, so that an older key can be
     * dropped from it. Each secret is opened (and so authenticated) before it is sealed again; a row that
     * cannot be opened aborts the whole unit and leaves the table untouched.
     *
     * @return the number of factors re-sealed
     */
    public int resealWithActiveKey() {
        AtomicInteger resealed = new AtomicInteger();
        tx.executeManaged(conn -> {
            resealed.set(0);
            List<String[]> rows = new ArrayList<>();
            try (PersistenceStatement stmt = conn.prepare(
                    "SELECT id, subject_id, secret, pending_secret FROM mfa_factors ORDER BY id FOR UPDATE");
                 QueryResult rs = stmt.executeQuery()) {
                while (rs.next()) {
                    RowCursor row = rs.row();
                    rows.add(new String[]{
                            row.getUuid(0).toString(), row.getUuid(1).toString(),
                            row.isNull(2) ? null : row.getString(2), row.isNull(3) ? null : row.getString(3)});
                }
            }
            for (String[] row : rows) {
                UUID id = UUID.fromString(row[0]);
                UUID subject = UUID.fromString(row[1]);
                String secret = sealOrNull(id, subject, COL_SECRET, openOrNull(id, subject, COL_SECRET, row[2]));
                String pending = sealOrNull(id, subject, COL_PENDING, openOrNull(id, subject, COL_PENDING, row[3]));
                try (PersistenceStatement stmt = conn.prepare(
                        "UPDATE mfa_factors SET secret = $1, pending_secret = $2 WHERE id = $3")) {
                    bindSealed(stmt, 0, secret);
                    bindSealed(stmt, 1, pending);
                    stmt.bindUuid(2, id);
                    stmt.executeUpdate();
                }
                resealed.incrementAndGet();
            }
        });
        return resealed.get();
    }

    private static void bindSealed(PersistenceStatement stmt, int index, String sealed) {
        if (sealed == null) {
            stmt.bindNull(index);
        } else {
            stmt.bindString(index, sealed);
        }
    }
}
