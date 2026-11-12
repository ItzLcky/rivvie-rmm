-- Day-to-day gaps: alert maintenance windows and snoozes, reminders, per-agent policy
-- exclusions, patch alerts and health, standing patch approvals.

-- When the agent's current connection started (the "stopped reporting" checks count from it).
ALTER TABLE agents ADD COLUMN connected_at timestamptz;
-- Since when a reboot has been pending (NULL when none is).
ALTER TABLE agents ADD COLUMN reboot_pending_since timestamptz;
UPDATE agents SET reboot_pending_since = coalesce(patch_scanned_at, now()) WHERE reboot_pending;

-- Times when alerts for a client, a site or one agent are held back: a one-off period
-- (`ends_at`, a snooze when it starts now) or a weekly window (`days`, like a site's patch
-- window). Alerts that open during one are kept but marked `suppressed`: no notifications,
-- no tickets, and they don't count against health. If they're still open when it ends,
-- they're announced then.
CREATE TABLE alert_mutes (
    id          uuid PRIMARY KEY,
    client_id   uuid REFERENCES clients(id) ON DELETE CASCADE,
    site_id     uuid REFERENCES sites(id) ON DELETE CASCADE,
    agent_id    uuid REFERENCES agents(id) ON DELETE CASCADE,
    starts_at   timestamptz,
    ends_at     timestamptz,
    days        smallint[],   -- 0 = Sunday ... 6 = Saturday
    start_time  time,
    minutes     integer CHECK (minutes BETWEEN 15 AND 10080),
    tz          text NOT NULL DEFAULT 'UTC',
    reason      text NOT NULL DEFAULT '',
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(client_id, site_id, agent_id) = 1),
    CHECK (CASE WHEN ends_at IS NOT NULL
                THEN days IS NULL AND (starts_at IS NULL OR starts_at < ends_at)
                ELSE cardinality(days) > 0 AND start_time IS NOT NULL AND minutes IS NOT NULL END)
);
CREATE INDEX ON alert_mutes (agent_id);
CREATE INDEX ON alert_mutes (site_id);
CREATE INDEX ON alert_mutes (client_id);

-- Whether alerts for the agent are held back at `at`.
CREATE FUNCTION agent_muted(agent uuid, at timestamptz) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT EXISTS (
        SELECT 1 FROM alert_mutes m, agents a JOIN sites s ON s.id = a.site_id
         WHERE a.id = agent AND (m.agent_id = a.id OR m.site_id = a.site_id OR m.client_id = s.client_id)
           AND CASE WHEN m.ends_at IS NOT NULL THEN at >= coalesce(m.starts_at, '-infinity') AND at < m.ends_at
                    ELSE in_maintenance_window(m.days, m.start_time, m.minutes, m.tz, at) END)
$$;

ALTER TABLE alerts ADD COLUMN suppressed boolean NOT NULL DEFAULT false;
-- Last time its channels were told about it (opened, or a reminder).
ALTER TABLE alerts ADD COLUMN last_notified_at timestamptz;
UPDATE alerts SET last_notified_at = opened_at;

-- Every path that opens an alert goes through INSERT, so the mute check lives here.
CREATE FUNCTION alerts_mark_suppressed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.suppressed := agent_muted(NEW.agent_id, now());
    IF NOT NEW.suppressed THEN
        NEW.last_notified_at := now();
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER alerts_suppressed BEFORE INSERT ON alerts FOR EACH ROW EXECUTE FUNCTION alerts_mark_suppressed();
CREATE INDEX alerts_suppressed ON alerts (id) WHERE suppressed AND resolved_at IS NULL;

-- Remind the policy's channels this often while an alert stays open and unacknowledged.
ALTER TABLE alert_policies ADD COLUMN renotify_minutes integer CHECK (renotify_minutes BETWEEN 15 AND 10080);
-- Agents the policy leaves out even though its client/site/OS covers them.
ALTER TABLE alert_policies ADD COLUMN excluded_agents uuid[] NOT NULL DEFAULT '{}';

ALTER TABLE alert_policies DROP CONSTRAINT alert_policies_kind_check;
ALTER TABLE alert_policies ADD CONSTRAINT alert_policies_kind_check
    CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'service', 'job_failed', 'log', 'security', 'patch'));

ALTER TABLE notifications DROP CONSTRAINT notifications_event_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_event_check CHECK (event IN ('opened', 'resolved', 'reminder', 'test'));

-- A person's approval or decline of an update for every agent in a scope (MSP-wide, one
-- client or one site), including agents that report the update later. The most specific
-- one applies; a decision on one agent's row (`patches.approval_manual`) beats them all.
CREATE TABLE patch_approvals (
    update_id   text NOT NULL,
    client_id   uuid REFERENCES clients(id) ON DELETE CASCADE,
    site_id     uuid REFERENCES sites(id) ON DELETE CASCADE,
    decision    text NOT NULL CHECK (decision IN ('approved', 'declined')),
    decided_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at  timestamptz NOT NULL DEFAULT now(),
    CHECK (site_id IS NULL OR client_id IS NOT NULL)
);
CREATE UNIQUE INDEX patch_approvals_scope ON patch_approvals (update_id, client_id, site_id) NULLS NOT DISTINCT;
