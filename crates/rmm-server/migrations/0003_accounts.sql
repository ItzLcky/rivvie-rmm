-- Sessions get a public id so they can be listed and revoked without exposing the token
-- hash, and a last-seen time for the idle timeout (RMM_SESSION_IDLE_HOURS).
ALTER TABLE user_sessions ADD COLUMN id uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE;
ALTER TABLE user_sessions ADD COLUMN last_seen_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX ON user_sessions (user_id);

-- Organisation-wide settings, edited by admins on the Company settings page. Single row.
CREATE TABLE company_settings (
    id                  boolean PRIMARY KEY DEFAULT true CHECK (id),
    company_name        text NOT NULL DEFAULT '',
    -- NULL = use RMM_SESSION_IDLE_HOURS
    session_idle_hours  integer CHECK (session_idle_hours BETWEEN 1 AND 168),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    updated_by          uuid REFERENCES users(id) ON DELETE SET NULL
);
INSERT INTO company_settings DEFAULT VALUES;
