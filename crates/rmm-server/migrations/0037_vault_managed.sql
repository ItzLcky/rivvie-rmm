-- The vault's system write path (docs/design/vault-managed.md): items the server itself keeps
-- (disk recovery keys, rotated local admin passwords, identity resets), written by
-- vault::put_managed and keyed by (client, kind, reference).

ALTER TABLE vault_items
    ADD COLUMN managed_kind text,
    -- Kept when the device is deleted: a recovery key must outlive the agent record (the
    -- hostname stays in the item's name).
    ADD COLUMN agent_id uuid REFERENCES agents(id) ON DELETE SET NULL,
    -- The caller's key for the item within its kind, e.g. "<agent id>:<volume>".
    ADD COLUMN managed_ref text,
    -- Caller-defined progress (LAPS: pending until the agent confirms the new password).
    ADD COLUMN managed_state text;

ALTER TABLE vault_items ADD CONSTRAINT vault_items_managed_kind_check
    CHECK (managed_kind IN ('disk_recovery', 'local_admin', 'identity'));
ALTER TABLE vault_items ADD CONSTRAINT vault_items_managed_ref_check
    CHECK ((managed_kind IS NULL) = (managed_ref IS NULL) AND char_length(managed_ref) BETWEEN 1 AND 200);
ALTER TABLE vault_items ADD CONSTRAINT vault_items_managed_state_check
    CHECK (managed_state IS NULL OR (managed_kind IS NOT NULL AND char_length(managed_state) BETWEEN 1 AND 40));

CREATE UNIQUE INDEX vault_items_managed ON vault_items (client_id, managed_kind, managed_ref) WHERE managed_kind IS NOT NULL;
CREATE INDEX vault_items_agent ON vault_items (agent_id) WHERE agent_id IS NOT NULL;
