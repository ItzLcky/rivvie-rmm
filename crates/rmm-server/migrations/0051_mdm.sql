-- Intune managed devices, read through a client's Entra connection (docs/design/mdm.md).
-- Read-only: no action is ever sent to Intune.

CREATE TABLE mdm_devices (
    id            uuid PRIMARY KEY,
    source_id     uuid NOT NULL REFERENCES identity_sources(id) ON DELETE CASCADE,
    external_id   text NOT NULL,
    name          text NOT NULL DEFAULT '',
    user_upn      text NOT NULL DEFAULT '',
    os            text NOT NULL DEFAULT '',
    os_version    text NOT NULL DEFAULT '',
    -- compliant, noncompliant, conflict, error, inGracePeriod, configManager, unknown
    compliance    text NOT NULL DEFAULT 'unknown',
    -- Disk encryption as Intune reports it. Not a sealed-value flag: `bool`, so the
    -- rotate::TABLES check (which looks for "*encrypted boolean") leaves it alone.
    encrypted     bool,
    -- company, personal, unknown
    ownership     text NOT NULL DEFAULT 'unknown',
    serial        text NOT NULL DEFAULT '',
    model         text NOT NULL DEFAULT '',
    manufacturer  text NOT NULL DEFAULT '',
    enrolled_at   timestamptz,
    -- When the device last checked in with Intune.
    last_sync_at  timestamptz,
    -- Our agent on the same machine: by serial number, else hostname, within the client.
    agent_id      uuid REFERENCES agents(id) ON DELETE SET NULL,
    synced_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source_id, external_id)
);
CREATE INDEX ON mdm_devices (agent_id);
