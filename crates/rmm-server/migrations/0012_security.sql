-- Phase 8, milestone 1: endpoint protection status and management.

-- When the agent last reported its protection state, and what went wrong reading it.
ALTER TABLE agents ADD COLUMN security_at    timestamptz;
ALTER TABLE agents ADD COLUMN security_error text;

-- The antivirus products an agent last reported, replaced on every report. kind is
-- defender, clamav, xprotect or other (a product registered with Windows Security Center).
CREATE TABLE security_products (
    agent_id               uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    kind                   text NOT NULL,
    name                   text NOT NULL,
    version                text,
    enabled                boolean,
    realtime               boolean,
    signature_version      text,
    signatures_updated_at  timestamptz,
    -- Security Center's verdict for products that don't give a date.
    signatures_current     boolean,
    last_quick_scan_at     timestamptz,
    last_full_scan_at      timestamptz,
    tamper_protection      boolean,
    -- quick_scan / full_scan / update_signatures the agent can start for it.
    actions                text[] NOT NULL DEFAULT '{}',
    detail                 text,
    PRIMARY KEY (agent_id, kind, name)
);

-- What the products found. One row per (agent, product, the product's detection id),
-- updated as its status changes. Open while the product reports it active; resolved once
-- it's dealt with or drops out of the product's list.
CREATE TABLE security_detections (
    id             uuid PRIMARY KEY,
    agent_id       uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    product        text NOT NULL,
    external_id    text NOT NULL,
    name           text NOT NULL,
    severity       text NOT NULL CHECK (severity IN ('severe', 'high', 'moderate', 'low', 'unknown')),
    status         text NOT NULL CHECK (status IN ('active', 'quarantined', 'removed', 'blocked', 'allowed', 'unknown')),
    resources      text[] NOT NULL DEFAULT '{}',
    process        text,
    username       text,
    -- When the product detected it, by the machine's clock.
    detected_at    timestamptz,
    first_seen_at  timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    resolved_at    timestamptz,
    UNIQUE (agent_id, product, external_id)
);
CREATE INDEX security_detections_open ON security_detections (agent_id) WHERE resolved_at IS NULL;
CREATE INDEX ON security_detections (first_seen_at DESC, id DESC);
CREATE INDEX ON security_detections (lower(name));

-- Scans and signature updates started from the console.
CREATE TABLE security_actions (
    id           uuid PRIMARY KEY,
    agent_id     uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    product      text NOT NULL,
    action       text NOT NULL CHECK (action IN ('quick_scan', 'full_scan', 'update_signatures')),
    status       text NOT NULL DEFAULT 'sent' CHECK (status IN ('sent', 'running', 'succeeded', 'failed', 'lost')),
    message      text,
    created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    finished_at  timestamptz
);
CREATE INDEX ON security_actions (agent_id, created_at DESC);
CREATE INDEX security_actions_live ON security_actions (agent_id) WHERE status IN ('sent', 'running');

-- Alert policies on protection state. params:
--   security: {"unprotected": true, "realtime_off": true, "signature_max_age_hours": 72, "threats": "active"}
--   threats is off, active (open while the threat is active) or any (every new detection,
--   even one already quarantined; stays open until someone resolves it).
ALTER TABLE alert_policies DROP CONSTRAINT alert_policies_kind_check;
ALTER TABLE alert_policies ADD CONSTRAINT alert_policies_kind_check
    CHECK (kind IN ('offline', 'cpu', 'memory', 'disk', 'service', 'job_failed', 'log', 'security'));
