-- Disk encryption status and BitLocker recovery-key escrow (docs/design/disk-encryption.md).
-- The agent reports the encryption state of its fixed volumes; the server keeps it here, pulls
-- BitLocker recovery passwords it hasn't escrowed yet into the client's vault (managed items of
-- kind `disk_recovery`), and alerts through `disk_encryption` alert items.

CREATE TABLE disk_volumes (
    agent_id               uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    -- `C:` on Windows, the mount point elsewhere.
    volume_id              text NOT NULL,
    mount                  text NOT NULL DEFAULT '',
    device                 text NOT NULL DEFAULT '',
    kind                   text NOT NULL CHECK (kind IN ('bitlocker', 'filevault', 'luks', 'none')),
    role                   text NOT NULL CHECK (role IN ('os', 'data')),
    status                 text NOT NULL CHECK (status IN ('encrypted', 'encrypting', 'decrypting', 'unencrypted', 'suspended', 'unknown')),
    percent                real,
    method                 text,
    -- Kinds of key protector: tpm, recovery_password, passphrase...
    protectors             text[] NOT NULL DEFAULT '{}',
    protection_on          boolean NOT NULL DEFAULT false,
    locked                 boolean NOT NULL DEFAULT false,
    -- The volume's BitLocker recovery password protector, as last reported, and the one whose
    -- password is in the vault.
    recovery_protector_id  text,
    escrowed_protector_id  text,
    escrowed_at            timestamptz,
    -- Why the last escrow attempt failed (the agent's message), until one succeeds.
    escrow_error           text,
    vault_item_id          uuid REFERENCES vault_items(id) ON DELETE SET NULL,
    -- Since when protection has been suspended (the alert's grace period counts from here).
    suspended_since        timestamptz,
    updated_at             timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, volume_id)
);
CREATE INDEX ON disk_volumes (status);

-- When the agent last reported, why it couldn't read everything, its TPM, and a summary of its
-- volumes for the device list: `encrypted` (all), `partial`, `none`, or NULL (never reported).
ALTER TABLE agents ADD COLUMN diskenc_at timestamptz,
                   ADD COLUMN diskenc_error text,
                   ADD COLUMN tpm jsonb,
                   ADD COLUMN diskenc_status text CHECK (diskenc_status IN ('encrypted', 'partial', 'none'));

-- The `disk_encryption` policy module: single-instance, in All devices. Every module list is
-- re-declared in full (0035's plus this one), as 0035 explains.
ALTER TABLE policy_items DROP CONSTRAINT IF EXISTS policy_items_module_check;
ALTER TABLE policy_items ADD CONSTRAINT policy_items_module_check
    CHECK (module IN ('alert', 'schedule', 'patch', 'security', 'remote_access', 'agent', 'software', 'automation', 'disk_encryption'));
CREATE UNIQUE INDEX policy_items_single_disk_encryption ON policy_items (module) WHERE module = 'disk_encryption';

INSERT INTO policy_items (id, set_id, module, name, config) VALUES
    ('00000000-0000-4000-8000-000000000005', '00000000-0000-4000-8001-000000000000', 'disk_encryption', 'Disk encryption',
     '{"escrow_recovery_keys": true, "add_recovery_protector": false}');
SELECT policy_rebuild(ARRAY['00000000-0000-4000-8000-000000000005'::uuid]);
