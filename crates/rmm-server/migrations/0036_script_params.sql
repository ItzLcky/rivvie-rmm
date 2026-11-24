-- Script parameters (docs/design/script-params.md): typed inputs a saved script declares, passed
-- to it as RMM_PARAM_<NAME> environment variables. The script body is never rewritten.

-- [{name, label, type, required, default, choices, description}], checked by params.rs.
ALTER TABLE scripts ADD COLUMN params jsonb NOT NULL DEFAULT '[]';

-- What a job was given, per device and after placeholders were expanded; a secret's value is
-- shown as "•••".
ALTER TABLE jobs ADD COLUMN params jsonb NOT NULL DEFAULT '{}';
-- The secret values of a job that hasn't reached its agent yet ({name: value} as JSON), sealed
-- with RMM_DATA_KEY (associated data "job-env:<job id>"). Always sealed; rotate-data-key
-- rewraps it.
ALTER TABLE jobs ADD COLUMN env_sealed bytea;

-- Secrets live only as long as they're needed: once the job is past queued/sent (finished,
-- failed, lost, expired...) they are dropped, whichever code path moved it.
CREATE FUNCTION jobs_drop_env() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.env_sealed := NULL;
    RETURN NEW;
END $$;

CREATE TRIGGER jobs_drop_env BEFORE INSERT OR UPDATE OF status, env_sealed ON jobs
    FOR EACH ROW WHEN (NEW.env_sealed IS NOT NULL AND NEW.status NOT IN ('queued', 'sent'))
    EXECUTE FUNCTION jobs_drop_env();
