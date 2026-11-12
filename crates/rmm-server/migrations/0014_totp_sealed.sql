-- TOTP secrets (totp_secret and totp_pending) sealed with RMM_DATA_KEY. Existing rows are
-- sealed at startup once the key is set.
ALTER TABLE users ADD COLUMN totp_sealed boolean NOT NULL DEFAULT false;
