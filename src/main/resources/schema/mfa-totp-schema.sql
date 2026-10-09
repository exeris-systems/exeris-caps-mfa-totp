-- DDL Schema for exeris-caps-mfa-totp
-- ADR-099: Layer 5 Domain Primitive MFA TOTP Factor, Recovery Codes & Challenge

CREATE TABLE IF NOT EXISTS mfa_factors (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL UNIQUE,
    secret VARCHAR(64) NOT NULL,
    pending_secret VARCHAR(64),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    enrolled_at TIMESTAMPTZ,
    last_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mfa_factors_subject ON mfa_factors (subject_id);

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id UUID PRIMARY KEY,
    subject_id UUID NOT NULL,
    code_hash VARCHAR(64) NOT NULL UNIQUE,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_subject ON mfa_recovery_codes (subject_id);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_hash ON mfa_recovery_codes (code_hash);

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
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_hash ON mfa_challenges (token_hash);
