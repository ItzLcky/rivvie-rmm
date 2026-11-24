-- The end-user tray app (docs/design/tray.md): its policy module, tickets made from a device,
-- and the board they go to.

-- `tray` joins the modules. The list is 0035's plus `disk_encryption` (0038) and `local_admin`
-- (0039), which were added in parallel; `tray` is single-instance, so the limit check is unchanged.
ALTER TABLE policy_items DROP CONSTRAINT IF EXISTS policy_items_module_check;
ALTER TABLE policy_items ADD CONSTRAINT policy_items_module_check
    CHECK (module IN ('alert', 'schedule', 'patch', 'security', 'remote_access', 'agent', 'software', 'automation',
                      'disk_encryption', 'local_admin', 'tray'));

INSERT INTO policy_items (id, set_id, module, name, config) VALUES
    ('00000000-0000-4000-8000-000000000007', '00000000-0000-4000-8001-000000000000', 'tray', 'Tray app',
     '{"enabled": true, "request_help": true, "contact_card": true, "screenshot_default": true, "links": []}')
ON CONFLICT (id) DO NOTHING;
SELECT policy_rebuild(ARRAY['00000000-0000-4000-8000-000000000007'::uuid]);

-- Tickets a person at a device asked for through the tray. `source_ref` is the agent's request
-- id: an agent that resends after a lost answer gets the same ticket back.
ALTER TABLE tickets DROP CONSTRAINT IF EXISTS tickets_source_check;
ALTER TABLE tickets ADD CONSTRAINT tickets_source_check CHECK (source IN ('dashboard', 'email', 'alert', 'portal', 'api', 'agent'));
ALTER TABLE tickets ADD COLUMN source_ref text;
CREATE UNIQUE INDEX tickets_source_ref ON tickets (source, source_ref) WHERE source_ref IS NOT NULL;

-- Where tray requests go; NULL: the portal's board.
ALTER TABLE company_settings ADD COLUMN tray_board_id uuid REFERENCES boards(id) ON DELETE SET NULL;
