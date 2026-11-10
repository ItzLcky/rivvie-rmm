-- Phase 8, milestones 2-7: our own sensor, content, response, investigation, prevention.

-- Permission sets: NULL = the role's defaults (readonly: security.read; technician: + security.respond;
-- admin: everything). A list replaces the defaults for that user.
ALTER TABLE users ADD COLUMN permissions text[];

-- The sensor as the agent last reported it (SensorStatus), and the content it runs.
ALTER TABLE agents ADD COLUMN sensor          jsonb;
ALTER TABLE agents ADD COLUMN sensor_at       timestamptz;
ALTER TABLE agents ADD COLUMN content_version text;
ALTER TABLE agents ADD COLUMN isolated        boolean NOT NULL DEFAULT false;

-- Canary clients get new detection content first.
ALTER TABLE clients ADD COLUMN security_canary boolean NOT NULL DEFAULT false;

-- What the sensor does. The most specific policy applies, whole: site, else client, else the
-- MSP-wide one (fixed id, created here, can't be deleted).
CREATE TABLE security_policies (
    id                uuid PRIMARY KEY,
    client_id         uuid REFERENCES clients(id) ON DELETE CASCADE,
    site_id           uuid REFERENCES sites(id) ON DELETE CASCADE,
    sensor_enabled    boolean NOT NULL DEFAULT false,
    quick_scan_hours  integer NOT NULL DEFAULT 24 CHECK (quick_scan_hours BETWEEN 0 AND 720),
    full_scan_days    integer NOT NULL DEFAULT 7 CHECK (full_scan_days BETWEEN 0 AND 90),
    auto_quarantine   boolean NOT NULL DEFAULT true,
    prevention        boolean NOT NULL DEFAULT false,
    canaries          boolean NOT NULL DEFAULT true,
    telemetry_mb      integer NOT NULL DEFAULT 128 CHECK (telemetry_mb BETWEEN 16 AND 4096),
    updated_by        uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CHECK (site_id IS NULL OR client_id IS NOT NULL),
    UNIQUE NULLS NOT DISTINCT (client_id, site_id)
);
INSERT INTO security_policies (id) VALUES ('00000000-0000-4000-8000-000000000002');

-- Allow-listing. client_id NULL = every client.
CREATE TABLE security_exclusions (
    id          uuid PRIMARY KEY,
    client_id   uuid REFERENCES clients(id) ON DELETE CASCADE,
    kind        text NOT NULL CHECK (kind IN ('path', 'sha256', 'rule', 'process')),
    value       text NOT NULL,
    comment     text NOT NULL DEFAULT '',
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON security_exclusions (client_id);

-- The server's say over a rule's mode (the kill switch is 'disabled').
CREATE TABLE security_rule_overrides (
    rule_id     text PRIMARY KEY,
    mode        text NOT NULL CHECK (mode IN ('disabled', 'audit', 'alert', 'block')),
    reason      text NOT NULL DEFAULT '',
    updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Signed content bundles. stage: canary (canary clients only) -> general (everyone);
-- rolled_back (pulled, automatically or by hand); retired (replaced by a newer general).
CREATE TABLE content_versions (
    id               uuid PRIMARY KEY,
    version          text NOT NULL UNIQUE,
    sha256           text NOT NULL,
    signature        text NOT NULL,
    bundle           bytea NOT NULL,
    description      text NOT NULL DEFAULT '',
    -- [{id, name, kind, severity, confidence, mode, mitre, digest}] for the rules view and
    -- for telling which rules a version changed.
    rules            jsonb NOT NULL DEFAULT '[]',
    hashes           integer NOT NULL DEFAULT 0,
    stage            text NOT NULL DEFAULT 'canary' CHECK (stage IN ('canary', 'general', 'rolled_back', 'retired')),
    stage_reason     text,
    uploaded_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    uploaded_at      timestamptz NOT NULL DEFAULT now(),
    stage_changed_at timestamptz NOT NULL DEFAULT now()
);

-- Files in quarantine on agents (the agent's list is authoritative).
CREATE TABLE quarantine_items (
    id               uuid PRIMARY KEY,
    agent_id         uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    path             text NOT NULL,
    sha256           text NOT NULL,
    size             bigint NOT NULL DEFAULT 0,
    reason           text,
    detection_ref    text,
    quarantined_at   timestamptz NOT NULL,
    state            text NOT NULL DEFAULT 'quarantined' CHECK (state IN ('quarantined', 'restored', 'deleted', 'gone')),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON quarantine_items (agent_id);
CREATE INDEX ON quarantine_items (sha256);

-- Sensor detections share the table with the platform products' ones.
ALTER TABLE security_detections ADD COLUMN source            text NOT NULL DEFAULT 'product' CHECK (source IN ('product', 'file', 'behaviour'));
ALTER TABLE security_detections ADD COLUMN rule_id           text;
ALTER TABLE security_detections ADD COLUMN mitre             text[] NOT NULL DEFAULT '{}';
ALTER TABLE security_detections ADD COLUMN audit             boolean NOT NULL DEFAULT false;
ALTER TABLE security_detections ADD COLUMN action_taken      text;
ALTER TABLE security_detections ADD COLUMN sha256            text;
-- Process tree and related events: JSON, encrypted with RMM_DATA_KEY when set (command lines
-- can hold credentials).
ALTER TABLE security_detections ADD COLUMN context           bytea;
ALTER TABLE security_detections ADD COLUMN context_encrypted boolean NOT NULL DEFAULT false;
ALTER TABLE security_detections ADD COLUMN content_version   text;
ALTER TABLE security_detections ADD COLUMN quarantine_id     uuid;
ALTER TABLE security_detections ADD COLUMN verdict           text CHECK (verdict IN ('true_positive', 'false_positive', 'benign'));
ALTER TABLE security_detections ADD COLUMN verdict_by        uuid REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE security_detections ADD COLUMN verdict_at        timestamptz;
ALTER TABLE security_detections ADD COLUMN notes             text;
CREATE INDEX ON security_detections (rule_id, first_seen_at) WHERE rule_id IS NOT NULL;
CREATE INDEX ON security_detections (sha256) WHERE sha256 IS NOT NULL;

-- Response actions share the actions table with scans.
ALTER TABLE security_actions DROP CONSTRAINT security_actions_action_check;
ALTER TABLE security_actions ADD CONSTRAINT security_actions_action_check CHECK (action IN (
    'quick_scan', 'full_scan', 'update_signatures', 'kill_process', 'quarantine_file', 'restore_file', 'delete_quarantined',
    'isolate', 'release', 'collect_triage', 'scan_path'));
ALTER TABLE security_actions ADD COLUMN params      jsonb NOT NULL DEFAULT '{}';
ALTER TABLE security_actions ADD COLUMN result      jsonb;
ALTER TABLE security_actions ADD COLUMN storage_key text;
ALTER TABLE security_actions ADD COLUMN detection_id uuid REFERENCES security_detections(id) ON DELETE SET NULL;
