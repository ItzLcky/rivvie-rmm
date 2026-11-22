-- Automation policies (docs/design/automations.md): event-triggered scripts and scripts that
-- run once per device, as `automation` items of the policy sets.

-- Policy items get a sixth module. The checks on policy_items name their modules, so they are
-- rebuilt (the constraints were unnamed: look them up).
DO $$
DECLARE c record;
BEGIN
    FOR c IN SELECT conname FROM pg_constraint WHERE conrelid = 'policy_items'::regclass AND contype = 'c' LOOP
        EXECUTE format('ALTER TABLE policy_items DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;
ALTER TABLE policy_items ADD CONSTRAINT policy_items_module_check
    CHECK (module IN ('alert', 'schedule', 'patch', 'security', 'remote_access', 'agent', 'automation'));
ALTER TABLE policy_items ADD CONSTRAINT policy_items_site_needs_client CHECK (site_id IS NULL OR client_id IS NOT NULL);
-- Only multi-instance modules take a limit (client, site, excluded agents).
ALTER TABLE policy_items ADD CONSTRAINT policy_items_limit_modules
    CHECK (module IN ('alert', 'schedule', 'automation') OR (client_id IS NULL AND cardinality(excluded_agents) = 0));

-- The first time an agent connected: the `enrollment` trigger fires when this is set, so it
-- fires once per device. Agents that have connected before the upgrade count as done.
ALTER TABLE agents ADD COLUMN first_connected_at timestamptz;
UPDATE agents SET first_connected_at = coalesce(connected_at, last_seen_at, enrolled_at)
 WHERE connected_at IS NOT NULL OR last_seen_at IS NOT NULL OR online;

-- One row per automation run on a device: the history on the agent's page and the per-device
-- state of `run_once` and `enrollment` automations (one row per item and agent, which is what
-- keeps them to once; a reset deletes the row).
--   waiting    held back (rate limit, or outside the site's maintenance window); starts when it can
--   pending    its job is queued or running
--   succeeded / failed   the job's outcome (a failed run is retried if the automation asks for it)
--   skipped    not run: `reason` says why (cooldown, rate_limited, expired, script_unavailable)
CREATE TABLE automation_runs (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    item_id      uuid NOT NULL REFERENCES policy_items(id) ON DELETE CASCADE,
    agent_id     uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    trigger      text NOT NULL CHECK (trigger IN ('enrollment', 'agent_online', 'alert_opened', 'patch_reboot_pending', 'run_once')),
    status       text NOT NULL CHECK (status IN ('waiting', 'pending', 'succeeded', 'failed', 'skipped')),
    reason       text,
    -- What fired it: the alert, the patch run, how long the agent was offline.
    context      jsonb NOT NULL DEFAULT '{}',
    job_id       uuid REFERENCES jobs(id) ON DELETE SET NULL,
    attempts     integer NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz
);
CREATE UNIQUE INDEX automation_runs_once ON automation_runs (item_id, agent_id) WHERE trigger IN ('enrollment', 'run_once');
CREATE INDEX automation_runs_agent ON automation_runs (agent_id, created_at DESC);
CREATE INDEX automation_runs_item ON automation_runs (item_id, status);
CREATE INDEX automation_runs_open ON automation_runs (status) WHERE status IN ('waiting', 'pending');
CREATE INDEX automation_runs_job ON automation_runs (job_id) WHERE job_id IS NOT NULL;
