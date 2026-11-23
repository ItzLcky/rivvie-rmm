-- Alerts about an SNMP-monitored network device (migration 0033) keep `agent_id` (the site's
-- designated agent) so the SIEM alert trigger of 0031 still fires for them; this adds the device
-- to the event so the `hostname` of the agent isn't mistaken for the thing that is down.
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
               'alert_kind', NEW.kind, 'severity', NEW.severity, 'title', NEW.title, 'details', NEW.details,
               'occurrences', NEW.occurrences, 'suppressed', NEW.suppressed, 'resolution', NEW.resolution,
               'opened_at', NEW.opened_at, 'acknowledged_at', NEW.acknowledged_at, 'resolved_at', NEW.resolved_at)
      FROM siem_destinations d
      JOIN agents a ON a.id = NEW.agent_id
      JOIN sites s ON s.id = a.site_id
      JOIN clients c ON c.id = s.client_id
      LEFT JOIN net_devices nd ON nd.id = NEW.device_id
     WHERE d.enabled AND d.send_alerts;
    RETURN NULL;
END $$;
