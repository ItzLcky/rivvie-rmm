-- Backup monitoring (docs/design/backups.md): the last result of the backup jobs on each
-- endpoint, as the agent read them (Windows Server Backup, Veeam, restic, borg, Time Machine,
-- the newest file in a folder). Alerts come from `backup` alert items of the device's own policy
-- set; this table is what the fleet view and the device's Backups card show.

CREATE TABLE backup_jobs (
    agent_id         uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    provider         text NOT NULL CHECK (provider IN ('wsb', 'veeam', 'restic', 'borg', 'timemachine', 'file_age')),
    -- The job's name in the product, or the repository or folder.
    job              text NOT NULL,
    last_run_at      timestamptz,
    last_success_at  timestamptz,
    last_result      text NOT NULL DEFAULT 'unknown' CHECK (last_result IN ('success', 'warning', 'failed', 'running', 'unknown')),
    message          text NOT NULL DEFAULT '',
    size_bytes       bigint,
    -- When the agent last reported it; jobs not reported for 30 days are dropped.
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, provider, job)
);
CREATE INDEX ON backup_jobs (last_result);
CREATE INDEX ON backup_jobs (last_success_at);
