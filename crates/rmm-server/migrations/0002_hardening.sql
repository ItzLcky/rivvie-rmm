-- Jobs that can no longer report back:
--   lost    = dispatched, but the agent disconnected or restarted before reporting a result
--   expired = queued for an agent that stayed offline past the queue retention window
ALTER TABLE jobs DROP CONSTRAINT jobs_status_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_status_check
    CHECK (status IN ('queued', 'sent', 'succeeded', 'failed', 'timed_out', 'error', 'cancelled', 'lost', 'expired'));
CREATE INDEX jobs_sent ON jobs (agent_id) WHERE status = 'sent';

-- Re-enrolling with only an enrollment token used to upsert on (site_id, machine_id) and
-- rotate the existing agent's secret. machine_id is not secret, so anyone with a site token
-- could take over an existing agent. Now a record is only reused when the enrolling agent
-- proves its old credential; otherwise a new record is created and the stale one can be
-- deleted from the dashboard. machine_id is kept for spotting duplicates.
DROP INDEX agents_site_machine;
CREATE INDEX agents_site_machine ON agents (site_id, machine_id) WHERE machine_id IS NOT NULL;
