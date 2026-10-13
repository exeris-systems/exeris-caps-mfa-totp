-- exeris-caps-mfa-totp: TOTP factors, recovery codes and login challenges (ADR-099, obligation 9).
--
-- mfa_factors.secret and mfa_factors.pending_secret hold AES-256-GCM envelopes (Base64), never a
-- plaintext seed; the envelope names the key that sealed it and binds the row id, subject and column.
-- A NULL column means "no secret": an empty string is not a sentinel.
-- last_accepted_step is the highest TOTP time step a verification accepted; a code is accepted only at
-- a greater step, so a code works once (RFC 6238 section 5.2).

CREATE TABLE IF NOT EXISTS mfa_factors (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL UNIQUE,
    secret TEXT,
    pending_secret TEXT,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    enrolled_at TIMESTAMPTZ,
    last_verified_at TIMESTAMPTZ,
    last_accepted_step BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL,
    code_hash VARCHAR(64) NOT NULL UNIQUE,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_subject ON mfa_recovery_codes (subject_id);

CREATE TABLE IF NOT EXISTS mfa_challenges (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    failed_attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_subject ON mfa_challenges (subject_id);
