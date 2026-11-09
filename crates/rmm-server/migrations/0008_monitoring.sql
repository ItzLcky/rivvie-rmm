-- Phase 4: monitoring and alerting.

-- Services the agent last reported (systemd units / Windows services), as a JSON array of
-- {name, display_name, state, start_mode}.
ALTER TABLE agents ADD COLUMN services    jsonb;
ALTER TABLE agents ADD COLUMN services_at timestamptz;

-- Where notifications go. config by kind:
--   email:   {"to": ["ops@example.com", ...]}
--   webhook: {"url": "https://...", "secret": "..."}   (secret optional; signs the body)
--   slack:   {"url": "https://hooks.slack.com/..."}
--   teams:   {"url": "https://...webhook..."}        (Teams Workflows incoming webhook)
CREATE TABLE notification_channels (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    kind        text NOT NULL CHECK (kind IN ('email', 'webhook', 'slack', 'teams')),
    config      jsonb NOT NULL DEFAULT '{}',
    enabled     boolean NOT NULL DEFAULT true,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Outgoing mail server for email channels. The password is stored as-is (like the TOTP
-- secrets), so a database leak exposes it: use an account that can only send.
ALTER TABLE company_settings ADD COLUMN smtp_host     text NOT NULL DEFAULT '';
ALTER TABLE company_settings ADD COLUMN smtp_port     integer NOT NULL DEFAULT 587 CHECK (smtp_port BETWEEN 1 AND 65535);
ALTER TABLE company_settings ADD COLUMN smtp_security text NOT NULL DEFAULT 'starttls' CHECK (smtp_security IN ('starttls', 'tls', 'none'));
ALTER TABLE company_settings ADD COLUMN smtp_username text NOT NULL DEFAULT '';
ALTER TABLE company_settings ADD COLUMN smtp_password text NOT NULL DEFAULT '';
ALTER TABLE company_settings ADD COLUMN smtp_from     text NOT NULL DEFAULT '';

-- What to alert on, and for which agents. client_id NULL = every client (admins only);
-- site_id narrows to one site of that client. params by kind:
--   offline:    {"minutes": 10}
--   cpu|memory: {"threshold": 90, "minutes": 15}           percent, held for the whole window
--   disk:       {"threshold": 90, "minutes": 5}            fullest volume
--   service:    {"services": ["nginx.service"], "auto_only": false, "exclude": []}
--   job_failed: {"script_id": null}                        null = any script, ad-hoc included
--   log:        {"channels": [], "sources": [], "event_ids": [], "min_level": "error", "pattern": null}
CREATE TABLE alert_policies (
    id               uuid PRIMARY KEY,
    name             text NOT NULL,
    kind             text NOT NULL CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'service', 'job_failed', 'log')),
    params           jsonb NOT NULL DEFAULT '{}',
    severity         text NOT NULL DEFAULT 'warning' CHECK (severity IN ('critical', 'warning', 'info')),
    client_id        uuid REFERENCES clients(id) ON DELETE CASCADE,
    site_id          uuid REFERENCES sites(id) ON DELETE CASCADE,
    os_family        text,
    channel_ids      uuid[] NOT NULL DEFAULT '{}',
    notify_resolved  boolean NOT NULL DEFAULT true,
    enabled          boolean NOT NULL DEFAULT true,
    created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (site_id IS NULL OR client_id IS NOT NULL)
);
CREATE INDEX ON alert_policies (client_id);

-- One row per incident. `key` tells apart several alerts from one policy on one agent
-- (a service name, a script id). At most one unresolved alert per (policy, agent, key).
CREATE TABLE alerts (
    id               uuid PRIMARY KEY,
    policy_id        uuid REFERENCES alert_policies(id) ON DELETE SET NULL,
    agent_id         uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    key              text NOT NULL DEFAULT '',
    kind             text NOT NULL,
    severity         text NOT NULL,
    title            text NOT NULL,
    details          jsonb NOT NULL DEFAULT '{}',
    -- How many times it fired while open (log matches, repeated job failures).
    occurrences      integer NOT NULL DEFAULT 1,
    opened_at        timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    acknowledged_at  timestamptz,
    acknowledged_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    resolved_at      timestamptz,
    resolved_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    -- Why it closed: 'cleared' (the condition went away), 'manual', 'policy' (policy changed or removed).
    resolution       text
);
CREATE UNIQUE INDEX alerts_open_key ON alerts (policy_id, agent_id, key) WHERE resolved_at IS NULL;
CREATE INDEX alerts_open_agent ON alerts (agent_id) WHERE resolved_at IS NULL;
CREATE INDEX alerts_opened ON alerts (opened_at DESC, id DESC);
CREATE INDEX alerts_agent ON alerts (agent_id, opened_at DESC);

-- Outbox: each alert event × channel is delivered (and retried) by a background worker.
CREATE TABLE notifications (
    id               bigserial PRIMARY KEY,
    channel_id       uuid NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    alert_id         uuid REFERENCES alerts(id) ON DELETE CASCADE,
    event            text NOT NULL CHECK (event IN ('opened', 'resolved', 'test')),
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts         integer NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_error       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    sent_at          timestamptz
);
CREATE INDEX notifications_due ON notifications (next_attempt_at) WHERE status = 'pending';
CREATE INDEX ON notifications (alert_id);
CREATE INDEX ON notifications (created_at);

-- Log entries that matched a `log` policy, kept for the agent's Event log tab.
CREATE TABLE log_events (
    id          bigserial PRIMARY KEY,
    agent_id    uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    policy_id   uuid REFERENCES alert_policies(id) ON DELETE SET NULL,
    alert_id    uuid REFERENCES alerts(id) ON DELETE SET NULL,
    ts          timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    level       text NOT NULL,
    source      text NOT NULL DEFAULT '',
    event_id    integer,
    message     text NOT NULL
);
CREATE INDEX ON log_events (agent_id, id DESC);
CREATE INDEX ON log_events (received_at);

-- Scheduled scripts. Targets every agent of the client (or just one site), optionally one OS.
-- client_id NULL = every client (admins only).
CREATE TABLE schedules (
    id            uuid PRIMARY KEY,
    name          text NOT NULL,
    script_id     uuid NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    client_id     uuid REFERENCES clients(id) ON DELETE CASCADE,
    site_id       uuid REFERENCES sites(id) ON DELETE CASCADE,
    os_family     text,
    cron          text NOT NULL,
    timezone      text NOT NULL DEFAULT 'UTC',
    args          jsonb NOT NULL DEFAULT '[]',
    timeout_secs  integer CHECK (timeout_secs BETWEEN 1 AND 86400),
    -- Finished runs are deleted after this many days.
    retain_days   integer NOT NULL DEFAULT 30 CHECK (retain_days BETWEEN 1 AND 3650),
    enabled       boolean NOT NULL DEFAULT true,
    next_run_at   timestamptz,
    last_run_at   timestamptz,
    created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CHECK (site_id IS NULL OR client_id IS NOT NULL)
);
CREATE INDEX schedules_due ON schedules (next_run_at) WHERE enabled;

ALTER TABLE jobs ADD COLUMN schedule_id uuid REFERENCES schedules(id) ON DELETE SET NULL;
CREATE INDEX jobs_schedule ON jobs (schedule_id, created_at DESC) WHERE schedule_id IS NOT NULL;

-- Hourly rollups of agent_metrics, so long chart ranges and long retention stay cheap.
-- Raw samples are kept for RMM_METRICS_RAW_DAYS, rollups for RMM_METRICS_RETENTION_DAYS.
CREATE TABLE agent_metrics_hourly (
    agent_id      uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    hour          timestamptz NOT NULL,
    samples       integer NOT NULL,
    cpu_avg       real NOT NULL,
    cpu_max       real NOT NULL,
    mem_used_avg  bigint NOT NULL,
    mem_used_max  bigint NOT NULL,
    mem_total     bigint NOT NULL,
    disk_max_pct  real NOT NULL,
    net_rx_bytes  bigint NOT NULL,
    net_tx_bytes  bigint NOT NULL,
    PRIMARY KEY (agent_id, hour)
);
CREATE INDEX ON agent_metrics_hourly (hour);

INSERT INTO agent_metrics_hourly
SELECT agent_id, date_trunc('hour', ts), count(*), avg(cpu_percent), max(cpu_percent), avg(mem_used)::bigint,
       max(mem_used), max(mem_total), max(disk_max_pct), max(net_rx_bytes), max(net_tx_bytes)
  FROM agent_metrics
 WHERE ts < date_trunc('hour', now())
 GROUP BY 1, 2;
