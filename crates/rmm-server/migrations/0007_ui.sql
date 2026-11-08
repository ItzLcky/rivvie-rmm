-- Phase 3 dashboard: per-user UI preferences (theme, table columns, density...), and
-- indexes for the keyset-paged job and audit lists.
ALTER TABLE users ADD COLUMN preferences jsonb NOT NULL DEFAULT '{}';

CREATE INDEX jobs_created ON jobs (created_at DESC, id DESC);
CREATE INDEX audit_log_ts_id ON audit_log (ts DESC, id DESC);
CREATE INDEX audit_log_target ON audit_log (target_type, target_id, ts DESC);
