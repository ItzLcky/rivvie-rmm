-- Uptime monitors (docs/design/uptime.md), run by an agent (step C1a of the parity plan).
--
-- A monitor pings a host, connects to a TCP port, fetches a URL, reads a server's TLS
-- certificate or looks up a DNS name, from an agent: the one named, or the site's designated
-- agent (site_network.agent_id, migration 0033). Results are kept raw for RMM_METRICS_RAW_DAYS
-- and as hourly rollups for RMM_METRICS_RETENTION_DAYS, like agent metrics. Alerts about a
-- monitor are ordinary alerts (`alerts.monitor_id`), opened by `uptime` alert items of the
-- runner agent's policy set, and like network-device alerts they don't count against that
-- agent's health. `runner = 'server'` is reserved for step C1b (checks run by the server).

CREATE TABLE uptime_monitors (
    id              uuid PRIMARY KEY,
    client_id       uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    site_id         uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name            text NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('ping', 'tcp', 'http', 'tls', 'dns')),
    -- Per kind: {host}, {host, port}, {url, method, statuses, keyword, keyword_absent, verify_tls},
    -- {host, port, server_name}, {name, record, server, expect}.
    config          jsonb NOT NULL DEFAULT '{}',
    runner          text NOT NULL DEFAULT 'agent' CHECK (runner IN ('agent', 'server')),
    -- NULL: the site's designated agent.
    agent_id        uuid REFERENCES agents(id) ON DELETE SET NULL,
    interval_secs   integer NOT NULL DEFAULT 60 CHECK (interval_secs BETWEEN 30 AND 86400),
    timeout_secs    integer NOT NULL DEFAULT 10 CHECK (timeout_secs BETWEEN 1 AND 120),
    enabled         boolean NOT NULL DEFAULT true,
    -- unknown: never checked, disabled, or the runner is offline or silent; up; down.
    state           text NOT NULL DEFAULT 'unknown' CHECK (state IN ('up', 'down', 'unknown')),
    state_since     timestamptz NOT NULL DEFAULT now(),
    -- Consecutive failed checks.
    fail_count      integer NOT NULL DEFAULT 0,
    last_at         timestamptz,
    last_ms         integer,
    last_message    text,
    -- HTTP status, certificate days left.
    last_value      double precision,
    cert_not_after  timestamptz,
    -- {subject, issuer, sans, not_before, not_after, untrusted}, as last seen.
    cert            jsonb,
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (client_id, name)
);
CREATE INDEX ON uptime_monitors (site_id);
CREATE INDEX ON uptime_monitors (agent_id) WHERE agent_id IS NOT NULL;

CREATE TABLE uptime_results (
    monitor_id  uuid NOT NULL REFERENCES uptime_monitors(id) ON DELETE CASCADE,
    ts          timestamptz NOT NULL,
    ok          boolean NOT NULL,
    ms          integer,
    message     text NOT NULL DEFAULT '',
    PRIMARY KEY (monitor_id, ts)
);
CREATE INDEX ON uptime_results (ts);

CREATE TABLE uptime_hourly (
    monitor_id  uuid NOT NULL REFERENCES uptime_monitors(id) ON DELETE CASCADE,
    hour        timestamptz NOT NULL,
    checks      integer NOT NULL,
    failures    integer NOT NULL,
    avg_ms      real,
    max_ms      integer,
    PRIMARY KEY (monitor_id, hour)
);
CREATE INDEX ON uptime_hourly (hour);

-- `agent_id` stays the agent that runs the monitor (the alert engine, notifications and tickets
-- work from an agent and its policy set).
ALTER TABLE alerts ADD COLUMN monitor_id uuid REFERENCES uptime_monitors(id) ON DELETE CASCADE;
CREATE INDEX alerts_monitor ON alerts (monitor_id, opened_at DESC) WHERE monitor_id IS NOT NULL;

-- A website being down is not the runner's health: only the agent's own alerts count (0033's
-- function, with monitor alerts left out as well as device alerts).
CREATE OR REPLACE FUNCTION refresh_agent_alerts(ids uuid[]) RETURNS void LANGUAGE sql AS $$
    UPDATE agents a SET open_alerts = x.n, alert_critical = x.c, alert_warning = x.w
      FROM (SELECT g.id, count(al.id)::int AS n,
                   coalesce(bool_or(al.severity = 'critical' AND NOT al.suppressed), false) AS c,
                   coalesce(bool_or(al.severity = 'warning' AND NOT al.suppressed), false) AS w
              FROM (SELECT DISTINCT unnest(ids) AS id) u JOIN agents g ON g.id = u.id
                   LEFT JOIN alerts al ON al.agent_id = g.id AND al.resolved_at IS NULL AND al.device_id IS NULL AND al.monitor_id IS NULL
             GROUP BY g.id) x
     WHERE a.id = x.id AND (a.open_alerts, a.alert_critical, a.alert_warning) IS DISTINCT FROM (x.n, x.c, x.w)
$$;

-- The SIEM alert event (0034's) names the monitor too, so the runner's hostname isn't taken for
-- the thing that is down.
CREATE OR REPLACE FUNCTION siem_enqueue_alert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    what text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        what := 'alert.opened';
    ELSIF NEW.resolved_at IS NOT NULL AND OLD.resolved_at IS NULL THEN
        what := 'alert.resolved';
    ELSIF NEW.acknowledged_at IS NOT NULL AND OLD.acknowledged_at IS NULL THEN
        what := 'alert.acknowledged';
    ELSE
        RETURN NULL;
    END IF;
    INSERT INTO siem_outbox (destination_id, source, event)
    SELECT d.id, 'alert', jsonb_build_object(
               'kind', 'alert', 'event', what, 'id', NEW.id, 'ts', now(),
               'agent_id', NEW.agent_id, 'hostname', a.hostname, 'client', c.name,
               'device_id', NEW.device_id, 'device_name', nd.name, 'device_host', nd.host,
               'monitor_id', NEW.monitor_id, 'monitor_name', um.name,
               'alert_kind', NEW.kind, 'severity', NEW.severity, 'title', NEW.title, 'details', NEW.details,
               'occurrences', NEW.occurrences, 'suppressed', NEW.suppressed, 'resolution', NEW.resolution,
               'opened_at', NEW.opened_at, 'acknowledged_at', NEW.acknowledged_at, 'resolved_at', NEW.resolved_at)
      FROM siem_destinations d
      JOIN agents a ON a.id = NEW.agent_id
      JOIN sites s ON s.id = a.site_id
      JOIN clients c ON c.id = s.client_id
      LEFT JOIN net_devices nd ON nd.id = NEW.device_id
      LEFT JOIN uptime_monitors um ON um.id = NEW.monitor_id
     WHERE d.enabled AND d.send_alerts;
    RETURN NULL;
END $$;
