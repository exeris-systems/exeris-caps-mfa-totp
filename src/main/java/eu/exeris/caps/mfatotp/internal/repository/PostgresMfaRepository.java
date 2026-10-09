package eu.exeris.caps.mfatotp.internal.repository;

import eu.exeris.kernel.spi.persistence.PersistenceStatement;
import eu.exeris.kernel.spi.persistence.QueryResult;
import eu.exeris.kernel.spi.persistence.RowCursor;
import eu.exeris.kernel.spi.persistence.TransactionalExecutor;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public final class PostgresMfaRepository implements MfaRepository {

    private final TransactionalExecutor tx;

    public PostgresMfaRepository(TransactionalExecutor tx) {
        this.tx = Objects.requireNonNull(tx, "TransactionalExecutor must not be null");
    }

    @Override
    public Optional<FactorRecord> findFactorBySubjectId(UUID subjectId) {
        String sql = """
                SELECT id, subject_id, secret, pending_secret, enabled, enrolled_at, last_verified_at, created_at, updated_at
                FROM mfa_factors
                WHERE subject_id = $1
                """;
        return tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindUuid(0, subjectId);
                try (QueryResult rs = stmt.executeQuery()) {
                    if (rs.next()) {
                        RowCursor row = rs.row();
                        return Optional.of(new FactorRecord(
                                row.getUuid(0),
                                row.getUuid(1),
                                row.getString(2),
                                row.getString(3),
                                row.getBoolean(4),
                                row.getInstant(5),
                                row.getInstant(6),
                                row.getInstant(7),
                                row.getInstant(8)
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
                INSERT INTO mfa_factors (id, subject_id, secret, pending_secret, enabled, enrolled_at, last_verified_at, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (subject_id) DO UPDATE SET
                    secret = EXCLUDED.secret,
                    pending_secret = EXCLUDED.pending_secret,
                    enabled = EXCLUDED.enabled,
                    enrolled_at = EXCLUDED.enrolled_at,
                    last_verified_at = EXCLUDED.last_verified_at,
                    updated_at = EXCLUDED.updated_at
                """;
        tx.executeManaged(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindUuid(0, record.id())
                    .bindUuid(1, record.subjectId())
                    .bindString(2, record.secret())
                    .bindString(3, record.pendingSecret() != null ? record.pendingSecret() : "")
                    .bindBoolean(4, record.enabled());

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

                stmt.executeUpdate();
            }
        });
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
        Long affected = tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindInstant(0, consumedAt)
                    .bindUuid(1, id);
                return stmt.executeUpdate();
            }
        });
        return affected != null && affected > 0;
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
        Long affected = tx.query(conn -> {
            try (PersistenceStatement stmt = conn.prepare(sql)) {
                stmt.bindInstant(0, consumedAt)
                    .bindUuid(1, challengeId);
                return stmt.executeUpdate();
            }
        });
        return affected != null && affected > 0;
    }
}
