-- TOTP two-factor auth. totp_secret set = 2FA on. totp_pending holds a secret from
-- setup until the first code confirms it. totp_last_step blocks code replay.
ALTER TABLE users ADD COLUMN totp_secret     bytea;
ALTER TABLE users ADD COLUMN totp_pending    bytea;
ALTER TABLE users ADD COLUMN totp_last_step  bigint;
ALTER TABLE users ADD COLUMN totp_enabled_at timestamptz;

-- Single-use, SHA-256 of the normalised code (50 bits of entropy each).
CREATE TABLE user_recovery_codes (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);

-- Admins always need 2FA; this extends the requirement to every user.
ALTER TABLE company_settings ADD COLUMN require_2fa_all boolean NOT NULL DEFAULT false;
