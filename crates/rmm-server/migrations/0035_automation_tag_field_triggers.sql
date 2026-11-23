-- Automations that start on a tag or a custom-field change (docs/design/automations.md), and
-- the merge fix-up of the two policy modules that were added in parallel.

-- `software` (0032) rebuilt the policy_items checks without `automation` (0030), and 0030's
-- without `software`: after both ran, neither module would accept its items on top of the
-- other. Both are multi-instance modules, so both take a limit.
ALTER TABLE policy_items DROP CONSTRAINT IF EXISTS policy_items_module_check;
ALTER TABLE policy_items DROP CONSTRAINT IF EXISTS policy_items_limit_check;
ALTER TABLE policy_items DROP CONSTRAINT IF EXISTS policy_items_limit_modules;
ALTER TABLE policy_items ADD CONSTRAINT policy_items_module_check
    CHECK (module IN ('alert', 'schedule', 'patch', 'security', 'remote_access', 'agent', 'software', 'automation'));
ALTER TABLE policy_items ADD CONSTRAINT policy_items_limit_check
    CHECK (module IN ('alert', 'schedule', 'software', 'automation') OR (client_id IS NULL AND cardinality(excluded_agents) = 0));

-- Two more triggers: `tag_added` (a chosen tag is put on a device) and `field_changed` (a chosen
-- custom field of a device changes, optionally to a chosen value). The check was unnamed.
DO $$
DECLARE c record;
BEGIN
    FOR c IN SELECT conname FROM pg_constraint
              WHERE conrelid = 'automation_runs'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%agent_online%' LOOP
        EXECUTE format('ALTER TABLE automation_runs DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;
ALTER TABLE automation_runs ADD CONSTRAINT automation_runs_trigger_check
    CHECK (trigger IN ('enrollment', 'agent_online', 'alert_opened', 'patch_reboot_pending', 'run_once', 'tag_added', 'field_changed'));
