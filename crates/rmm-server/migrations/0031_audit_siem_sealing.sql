-- Audit log export and the SIEM stream (docs/design/audit-siem.md), and the credentials that
-- were stored in the clear, sealed with RMM_DATA_KEY like the other secrets.

-- ---------------------------------------------------------------------------------------------
-- Sealing: IMAP and SMTP passwords, and the HMAC secret of webhook notification channels.
--
-- Each plaintext column becomes a bytea plus a `*_sealed` flag. The migration can't seal (it
-- doesn't have the key): it moves the text over with the flag false, and the server seals
-- every such row at startup once RMM_DATA_KEY is set, like the TOTP and SSO secrets. The old
-- column is blanked before it is dropped, so the plaintext isn't left in the new row versions
-- (older versions stay in dead tuples until autovacuum, and in earlier backups: rotate the
-- passwords if that matters to you).
-- ---------------------------------------------------------------------------------------------
ALTER TABLE mailboxes
    ADD COLUMN imap_password_enc    bytea,
    ADD COLUMN imap_password_sealed boolean NOT NULL DEFAULT false;
UPDATE mailboxes
   SET imap_password_enc = CASE WHEN imap_password <> '' THEN convert_to(imap_password, 'UTF8') END,
       imap_password = '';
ALTER TABLE mailboxes DROP COLUMN imap_password;

ALTER TABLE company_settings
    ADD COLUMN smtp_password_enc    bytea,
    ADD COLUMN smtp_password_sealed boolean NOT NULL DEFAULT false;
UPDATE company_settings
   SET smtp_password_enc = CASE WHEN smtp_password <> '' THEN convert_to(smtp_password, 'UTF8') END,
       smtp_password = '';
ALTER TABLE company_settings DROP COLUMN smtp_password;

-- A webhook channel's signing secret used to sit in `config` (a jsonb the channel list returned
-- to admins minus this key).
ALTER TABLE notification_channels
    ADD COLUMN secret        bytea,
    ADD COLUMN secret_sealed boolean NOT NULL DEFAULT false;
UPDATE notification_channels
   SET secret = CASE WHEN coalesce(config ->> 'secret', '') <> '' THEN convert_to(config ->> 'secret', 'UTF8') END,
       config = config - 'secret'
 WHERE config ? 'secret';

-- ---------------------------------------------------------------------------------------------
-- SIEM destinations
-- ---------------------------------------------------------------------------------------------

-- Where audit events (and optionally security detections and alerts) are streamed. `address`
-- is `host:port` for the syslog kinds and a full URL for https. `token` (the bearer or Splunk
-- HEC token) is sealed with RMM_DATA_KEY when that is set.
CREATE TABLE siem_destinations (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  text NOT NULL UNIQUE,
    kind                  text NOT NULL CHECK (kind IN ('syslog_udp', 'syslog_tcp', 'syslog_tls', 'https')),
    address               text NOT NULL,
    -- Syslog over TCP: RFC 6587 octet counting or newline-delimited. TLS always counts octets (RFC 5425).
    framing               text NOT NULL DEFAULT 'octet' CHECK (framing IN ('octet', 'newline')),
    -- https: a JSON body {"events": [...]}, or Splunk HEC events.
    https_format          text NOT NULL DEFAULT 'generic' CHECK (https_format IN ('generic', 'splunk_hec')),
    token                 bytea,
    token_sealed          boolean NOT NULL DEFAULT false,
    -- An extra root certificate (PEM) to trust for TLS and https, for a collector with a private CA.
    ca_pem                text,
    -- Syslog facility (13 = log audit).
    facility              smallint NOT NULL DEFAULT 13 CHECK (facility BETWEEN 0 AND 23),
    send_audit            boolean NOT NULL DEFAULT true,
    send_detections       boolean NOT NULL DEFAULT false,
    send_alerts           boolean NOT NULL DEFAULT false,
    enabled               boolean NOT NULL DEFAULT true,
    -- Delivery status, shown on the settings page.
    consecutive_failures  integer NOT NULL DEFAULT 0,
    next_attempt_at       timestamptz NOT NULL DEFAULT now(),
    last_attempt_at       timestamptz,
    last_success_at       timestamptz,
    last_error            text,
    sent_total            bigint NOT NULL DEFAULT 0,
    -- Events deleted unsent because they were older than the outbox retention.
    dropped_total         bigint NOT NULL DEFAULT 0,
    created_by            uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now()
);

-- The outbox: one row per event per destination, written by the triggers below in the
-- transaction that wrote the event, so nothing is lost across a restart or an outage. The
-- worker sends a destination's rows in id order and deletes them once sent.
CREATE TABLE siem_outbox (
    id              bigserial PRIMARY KEY,
    destination_id  uuid NOT NULL REFERENCES siem_destinations(id) ON DELETE CASCADE,
    source          text NOT NULL CHECK (source IN ('audit', 'detection', 'alert')),
    event           jsonb NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX siem_outbox_destination ON siem_outbox (destination_id, id);
CREATE INDEX siem_outbox_created ON siem_outbox (created_at);

-- Audit log: every row.
CREATE FUNCTION siem_enqueue_audit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO siem_outbox (destination_id, source, event)
    SELECT d.id, 'audit', jsonb_build_object(
               'kind', 'audit', 'event', 'audit.' || NEW.action, 'id', NEW.id, 'ts', NEW.ts, 'action', NEW.action,
               'user_id', NEW.user_id, 'user_email', (SELECT u.email FROM users u WHERE u.id = NEW.user_id),
               'target_type', NEW.target_type, 'target_id', NEW.target_id, 'details', NEW.details)
      FROM siem_destinations d
     WHERE d.enabled AND d.send_audit;
    RETURN NULL;
END $$;
CREATE TRIGGER siem_audit AFTER INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION siem_enqueue_audit();

-- Detections: when one is first seen, and when its status changes or it resolves. Never the
-- (sealed) context: command lines can carry passwords.
CREATE FUNCTION siem_enqueue_detection() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    what text;
BEGIN
    IF TG_OP = 'INSERT' THEN
        what := 'detection.created';
    ELSIF NEW.resolved_at IS NOT NULL AND OLD.resolved_at IS NULL THEN
        what := 'detection.resolved';
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        what := 'detection.status_changed';
    ELSE
        RETURN NULL;
    END IF;
    INSERT INTO siem_outbox (destination_id, source, event)
    SELECT d.id, 'detection', jsonb_build_object(
               'kind', 'detection', 'event', what, 'id', NEW.id, 'ts', now(),
               'agent_id', NEW.agent_id, 'hostname', a.hostname, 'client', c.name,
               'product', NEW.product, 'name', NEW.name, 'severity', NEW.severity, 'status', NEW.status,
               'source', NEW.source, 'rule_id', NEW.rule_id, 'mitre', NEW.mitre, 'resources', NEW.resources,
               'process', NEW.process, 'username', NEW.username, 'sha256', NEW.sha256, 'action_taken', NEW.action_taken,
               'first_seen_at', NEW.first_seen_at, 'resolved_at', NEW.resolved_at)
      FROM siem_destinations d
      JOIN agents a ON a.id = NEW.agent_id
      JOIN sites s ON s.id = a.site_id
      JOIN clients c ON c.id = s.client_id
     WHERE d.enabled AND d.send_detections;
    RETURN NULL;
END $$;
CREATE TRIGGER siem_detection_insert AFTER INSERT ON security_detections FOR EACH ROW EXECUTE FUNCTION siem_enqueue_detection();
CREATE TRIGGER siem_detection_update AFTER UPDATE OF status, resolved_at ON security_detections
    FOR EACH ROW EXECUTE FUNCTION siem_enqueue_detection();

-- Alerts: opened, acknowledged, resolved.
CREATE FUNCTION siem_enqueue_alert() RETURNS trigger LANGUAGE plpgsql AS $$
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
               'alert_kind', NEW.kind, 'severity', NEW.severity, 'title', NEW.title, 'details', NEW.details,
               'occurrences', NEW.occurrences, 'suppressed', NEW.suppressed, 'resolution', NEW.resolution,
               'opened_at', NEW.opened_at, 'acknowledged_at', NEW.acknowledged_at, 'resolved_at', NEW.resolved_at)
      FROM siem_destinations d
      JOIN agents a ON a.id = NEW.agent_id
      JOIN sites s ON s.id = a.site_id
      JOIN clients c ON c.id = s.client_id
     WHERE d.enabled AND d.send_alerts;
    RETURN NULL;
END $$;
CREATE TRIGGER siem_alert_insert AFTER INSERT ON alerts FOR EACH ROW EXECUTE FUNCTION siem_enqueue_alert();
CREATE TRIGGER siem_alert_update AFTER UPDATE OF acknowledged_at, resolved_at ON alerts
    FOR EACH ROW EXECUTE FUNCTION siem_enqueue_alert();
