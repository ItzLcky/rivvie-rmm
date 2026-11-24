-- Alerts without an agent (step C1b of the parity plan, docs/design/uptime.md).
--
-- Until now every alert belonged to an agent, and its client was read through agent → site.
-- Uptime monitors run by the server have no agent, so an alert now carries its own client, and
-- `agent_id` is NULL for alerts that aren't about (or checked through) a device. Every query
-- reads the client from the alert and joins agents with LEFT JOIN.

ALTER TABLE alerts ADD COLUMN client_id uuid REFERENCES clients(id) ON DELETE CASCADE;
UPDATE alerts al SET client_id = s.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = al.agent_id;
ALTER TABLE alerts ALTER COLUMN client_id SET NOT NULL;
ALTER TABLE alerts ALTER COLUMN agent_id DROP NOT NULL;
CREATE INDEX alerts_client ON alerts (client_id, opened_at DESC);

-- One open alert per (policy, agent, key) still holds for agents; without an agent the
-- client takes its place (NULLs would never conflict).
CREATE UNIQUE INDEX alerts_open_key_agentless ON alerts (policy_id, client_id, key) WHERE resolved_at IS NULL AND agent_id IS NULL;

-- Whether an alert is held back at `at`: an agent's alerts by the agent's mutes (as before);
-- one without an agent by its client's mutes, and its monitor's site's.
CREATE FUNCTION alert_muted(agent uuid, client uuid, monitor uuid, at timestamptz) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN agent IS NOT NULL THEN agent_muted(agent, at) ELSE EXISTS (
        SELECT 1 FROM alert_mutes m
         WHERE (m.client_id = client OR m.site_id = (SELECT um.site_id FROM uptime_monitors um WHERE um.id = monitor))
           AND CASE WHEN m.ends_at IS NOT NULL THEN at >= coalesce(m.starts_at, '-infinity') AND at < m.ends_at
                    ELSE in_maintenance_window(m.days, m.start_time, m.minutes, m.tz, at) END) END
$$;

-- Every path that opens an alert goes through INSERT: the client is filled in from the agent
-- when the caller didn't give one, and the mute check (0015's) covers alerts without an agent.
CREATE OR REPLACE FUNCTION alerts_mark_suppressed() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.client_id IS NULL AND NEW.agent_id IS NOT NULL THEN
        SELECT s.client_id INTO NEW.client_id FROM agents a JOIN sites s ON s.id = a.site_id WHERE a.id = NEW.agent_id;
    END IF;
    NEW.suppressed := alert_muted(NEW.agent_id, NEW.client_id, NEW.monitor_id, now());
    IF NOT NEW.suppressed THEN
        NEW.last_notified_at := now();
    END IF;
    RETURN NEW;
END $$;

-- `refresh_agent_alerts` (0040's) needs no change: an alert without an agent counts against
-- nobody's health, and monitor alerts still don't count against their runner's.

-- The SIEM alert event (0040's, with the monitor): the client from the alert, the agent's
-- hostname when there is one.
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
               'agent_id', NEW.agent_id, 'hostname', a.hostname, 'client_id', NEW.client_id, 'client', c.name,
               'device_id', NEW.device_id, 'device_name', nd.name, 'device_host', nd.host,
               'monitor_id', NEW.monitor_id, 'monitor_name', um.name,
               'alert_kind', NEW.kind, 'severity', NEW.severity, 'title', NEW.title, 'details', NEW.details,
               'occurrences', NEW.occurrences, 'suppressed', NEW.suppressed, 'resolution', NEW.resolution,
               'opened_at', NEW.opened_at, 'acknowledged_at', NEW.acknowledged_at, 'resolved_at', NEW.resolved_at)
      FROM siem_destinations d
      JOIN clients c ON c.id = NEW.client_id
      LEFT JOIN agents a ON a.id = NEW.agent_id
      LEFT JOIN net_devices nd ON nd.id = NEW.device_id
      LEFT JOIN uptime_monitors um ON um.id = NEW.monitor_id
     WHERE d.enabled AND d.send_alerts;
    RETURN NULL;
END $$;
