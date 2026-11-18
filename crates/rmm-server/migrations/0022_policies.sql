-- Policy management (docs/design/policies.md): device categories, a tree of policy sets with
-- per-field overrides, assignments and pins. Replaces alert_policies, patch_policies,
-- security_policies, schedules, clients.desktop_consent and company_settings.auto_update_agents,
-- carrying their rows over so an existing install behaves the same.

-- Objects merge key by key, recursively; anything else in `b` (scalar, array, null) replaces.
CREATE FUNCTION jsonb_merge_deep(a jsonb, b jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN jsonb_typeof(a) = 'object' AND jsonb_typeof(b) = 'object' THEN
        coalesce((SELECT jsonb_object_agg(k, CASE WHEN a ? k AND b ? k THEN jsonb_merge_deep(a -> k, b -> k)
                                                  WHEN b ? k THEN b -> k ELSE a -> k END)
                    FROM (SELECT jsonb_object_keys(a) UNION SELECT jsonb_object_keys(b)) t(k)), '{}'::jsonb)
    ELSE b END
$$;

-- ---------------------------------------------------------------------------
-- Policy sets: one tree under "All devices". client_id NULL = MSP-wide; a client's set only
-- serves that client's devices, and its children belong to the same client.
-- ---------------------------------------------------------------------------
CREATE TABLE policy_sets (
    id           uuid PRIMARY KEY,
    -- Deleting a set with children is refused by the API; this only matters when a client
    -- (and with it all of its sets) is deleted.
    parent_id    uuid REFERENCES policy_sets(id) ON DELETE CASCADE,
    client_id    uuid REFERENCES clients(id) ON DELETE CASCADE,
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',
    -- The ten fixed sets: never deleted or moved, may be renamed.
    builtin      boolean NOT NULL DEFAULT false,
    created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    CHECK ((parent_id IS NULL) = (id = '00000000-0000-4000-8001-000000000000'))
);
CREATE INDEX ON policy_sets (parent_id);
CREATE INDEX ON policy_sets (client_id);

INSERT INTO policy_sets (id, parent_id, name, builtin) VALUES
    ('00000000-0000-4000-8001-000000000000', NULL, 'All devices', true),
    ('00000000-0000-4000-8001-000000000001', '00000000-0000-4000-8001-000000000000', 'Windows', true),
    ('00000000-0000-4000-8001-000000000011', '00000000-0000-4000-8001-000000000001', 'Windows workstations', true),
    ('00000000-0000-4000-8001-000000000012', '00000000-0000-4000-8001-000000000001', 'Windows servers', true),
    ('00000000-0000-4000-8001-000000000002', '00000000-0000-4000-8001-000000000000', 'Linux', true),
    ('00000000-0000-4000-8001-000000000021', '00000000-0000-4000-8001-000000000002', 'Linux workstations', true),
    ('00000000-0000-4000-8001-000000000022', '00000000-0000-4000-8001-000000000002', 'Linux servers', true),
    ('00000000-0000-4000-8001-000000000003', '00000000-0000-4000-8001-000000000000', 'macOS', true),
    ('00000000-0000-4000-8001-000000000031', '00000000-0000-4000-8001-000000000003', 'macOS workstations', true),
    ('00000000-0000-4000-8001-000000000032', '00000000-0000-4000-8001-000000000003', 'macOS servers', true);

-- ---------------------------------------------------------------------------
-- Device categories: every agent is in exactly one. The six built-ins ({OS} x {platform}) are
-- where agents go automatically; custom ones are folders a technician moves agents into.
-- ---------------------------------------------------------------------------
CREATE TABLE device_categories (
    id              uuid PRIMARY KEY,
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    builtin         boolean NOT NULL DEFAULT false,
    -- Built-ins only: what lands here automatically.
    os_family       text CHECK (os_family IN ('windows', 'linux', 'macos')),
    platform        text CHECK (platform IN ('workstation', 'server')),
    -- Devices without an assignment or pin use this set. MSP-wide sets only.
    default_set_id  uuid NOT NULL REFERENCES policy_sets(id),
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (builtin = (os_family IS NOT NULL AND platform IS NOT NULL))
);
CREATE UNIQUE INDEX device_categories_name ON device_categories (lower(name));

INSERT INTO device_categories (id, name, builtin, os_family, platform, default_set_id) VALUES
    ('00000000-0000-4000-8002-000000000011', 'Windows workstations', true, 'windows', 'workstation', '00000000-0000-4000-8001-000000000011'),
    ('00000000-0000-4000-8002-000000000012', 'Windows servers', true, 'windows', 'server', '00000000-0000-4000-8001-000000000012'),
    ('00000000-0000-4000-8002-000000000021', 'Linux workstations', true, 'linux', 'workstation', '00000000-0000-4000-8001-000000000021'),
    ('00000000-0000-4000-8002-000000000022', 'Linux servers', true, 'linux', 'server', '00000000-0000-4000-8001-000000000022'),
    ('00000000-0000-4000-8002-000000000031', 'macOS workstations', true, 'macos', 'workstation', '00000000-0000-4000-8001-000000000031'),
    ('00000000-0000-4000-8002-000000000032', 'macOS servers', true, 'macos', 'server', '00000000-0000-4000-8001-000000000032');

-- Which set a client's devices of one category use (site_id: just that site's).
CREATE TABLE policy_assignments (
    id             uuid PRIMARY KEY,
    client_id      uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    site_id        uuid REFERENCES sites(id) ON DELETE CASCADE,
    category_id    uuid NOT NULL REFERENCES device_categories(id) ON DELETE CASCADE,
    -- The API refuses to delete an assigned set; this is for a client's sets going with it.
    policy_set_id  uuid NOT NULL REFERENCES policy_sets(id) ON DELETE CASCADE,
    updated_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (client_id, site_id, category_id)
);
CREATE INDEX ON policy_assignments (policy_set_id);
CREATE INDEX ON policy_assignments (site_id, category_id);

-- ---------------------------------------------------------------------------
-- Policies (items) and per-set overrides.
-- ---------------------------------------------------------------------------
-- config by module (docs/design/policies.md):
--   alert:          {kind, params, severity, channel_ids, notify_resolved, renotify_minutes,
--                    ticket_board_id, ticket_priority, ticket_auto_resolve, run_script_id}
--   schedule:       {script_id, cron, timezone, args, timeout_secs, retain_days}
--   patch:          {auto_approve_severities, auto_approve_categories, deferral_days, auto_install,
--                    reboot_policy, window}           window: null = the site's, or {days, start, minutes, tz}
--   security:       the sensor policy's fields
--   remote_access:  {desktop_enabled, desktop_consent, shell_enabled, files_enabled}
--   agent:          {auto_update}
-- The limit (client, site, excluded agents) narrows alert and schedule items and can't be
-- overridden.
CREATE TABLE policy_items (
    id               uuid PRIMARY KEY,
    set_id           uuid NOT NULL REFERENCES policy_sets(id) ON DELETE CASCADE,
    module           text NOT NULL CHECK (module IN ('alert', 'schedule', 'patch', 'security', 'remote_access', 'agent')),
    name             text NOT NULL,
    enabled          boolean NOT NULL DEFAULT true,
    config           jsonb NOT NULL DEFAULT '{}',
    client_id        uuid REFERENCES clients(id) ON DELETE CASCADE,
    site_id          uuid REFERENCES sites(id) ON DELETE CASCADE,
    excluded_agents  uuid[] NOT NULL DEFAULT '{}',
    created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (site_id IS NULL OR client_id IS NOT NULL),
    CHECK (module IN ('alert', 'schedule') OR (client_id IS NULL AND cardinality(excluded_agents) = 0))
);
CREATE INDEX ON policy_items (set_id);
CREATE INDEX ON policy_items (client_id);
-- Single-instance modules live once, in All devices.
CREATE UNIQUE INDEX policy_items_single ON policy_items (module) WHERE module IN ('patch', 'security', 'remote_access', 'agent');

-- A descendant set's changes to an inherited item: config holds only the fields that differ,
-- enabled NULL = as inherited.
CREATE TABLE policy_overrides (
    item_id     uuid NOT NULL REFERENCES policy_items(id) ON DELETE CASCADE,
    set_id      uuid NOT NULL REFERENCES policy_sets(id) ON DELETE CASCADE,
    enabled     boolean,
    config      jsonb NOT NULL DEFAULT '{}',
    updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (item_id, set_id)
);
CREATE INDEX ON policy_overrides (set_id);

-- The merged result for every set an item reaches, so hot paths never walk the tree. Kept by
-- policy_rebuild() in the same transaction as every change to sets, items or overrides.
CREATE TABLE policy_effective (
    set_id   uuid NOT NULL REFERENCES policy_sets(id) ON DELETE CASCADE,
    item_id  uuid NOT NULL REFERENCES policy_items(id) ON DELETE CASCADE,
    module   text NOT NULL,
    enabled  boolean NOT NULL,
    config   jsonb NOT NULL,
    PRIMARY KEY (set_id, item_id)
);
CREATE INDEX ON policy_effective (item_id);

-- When each schedule item runs next.
CREATE TABLE policy_schedule_state (
    item_id      uuid PRIMARY KEY REFERENCES policy_items(id) ON DELETE CASCADE,
    next_run_at  timestamptz,
    last_run_at  timestamptz
);
CREATE INDEX policy_schedule_due ON policy_schedule_state (next_run_at);

-- Recomputes policy_effective for these items (NULL: all of them), writing only what changed.
CREATE FUNCTION policy_rebuild(items uuid[]) RETURNS void LANGUAGE sql AS $$
    WITH RECURSIVE eff AS (
        SELECT i.set_id, i.id AS item_id, i.module, i.enabled, i.config
          FROM policy_items i WHERE items IS NULL OR i.id = ANY(items)
        UNION ALL
        SELECT c.id, e.item_id, e.module, coalesce(o.enabled, e.enabled),
               CASE WHEN o.config IS NULL THEN e.config ELSE jsonb_merge_deep(e.config, o.config) END
          FROM eff e JOIN policy_sets c ON c.parent_id = e.set_id
          LEFT JOIN policy_overrides o ON o.item_id = e.item_id AND o.set_id = c.id),
    gone AS (
        DELETE FROM policy_effective p
         WHERE (items IS NULL OR p.item_id = ANY(items))
           AND NOT EXISTS (SELECT 1 FROM eff WHERE eff.set_id = p.set_id AND eff.item_id = p.item_id))
    INSERT INTO policy_effective (set_id, item_id, module, enabled, config)
    SELECT set_id, item_id, module, enabled, config FROM eff
    ON CONFLICT (set_id, item_id) DO UPDATE SET enabled = EXCLUDED.enabled, config = EXCLUDED.config
     WHERE (policy_effective.enabled, policy_effective.config) IS DISTINCT FROM (EXCLUDED.enabled, EXCLUDED.config)
$$;


-- ---------------------------------------------------------------------------
-- Agents: platform, category, pin, and the set they use.
-- ---------------------------------------------------------------------------
-- Agents that don't report a platform (older builds): Linux hosts and Windows Server editions
-- are servers (the rule billing used).
CREATE FUNCTION policy_platform(os_family text, os_name text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN lower(os_family) = 'linux' OR os_name ILIKE '%server%' THEN 'server' ELSE 'workstation' END
$$;

-- The built-in category for an OS and platform ('other' goes to Linux servers).
CREATE FUNCTION policy_builtin_category(os_family text, platform text) RETURNS uuid LANGUAGE sql IMMUTABLE AS $$
    SELECT (CASE lower(os_family)
                WHEN 'windows' THEN CASE platform WHEN 'workstation' THEN '00000000-0000-4000-8002-000000000011' ELSE '00000000-0000-4000-8002-000000000012' END
                WHEN 'macos' THEN CASE platform WHEN 'server' THEN '00000000-0000-4000-8002-000000000032' ELSE '00000000-0000-4000-8002-000000000031' END
                WHEN 'linux' THEN CASE platform WHEN 'workstation' THEN '00000000-0000-4000-8002-000000000021' ELSE '00000000-0000-4000-8002-000000000022' END
                ELSE '00000000-0000-4000-8002-000000000022' END)::uuid
$$;

-- The one set a device uses: its pin, else the assignment for its site and category, else the
-- one for its client and category, else the category's default.
CREATE FUNCTION policy_set_for(pin uuid, site uuid, category uuid) RETURNS uuid LANGUAGE sql STABLE AS $$
    SELECT coalesce(pin,
        (SELECT pa.policy_set_id FROM policy_assignments pa WHERE pa.site_id = site AND pa.category_id = category),
        (SELECT pa.policy_set_id FROM policy_assignments pa JOIN sites s ON s.client_id = pa.client_id
          WHERE s.id = site AND pa.site_id IS NULL AND pa.category_id = category),
        (SELECT dc.default_set_id FROM device_categories dc WHERE dc.id = category))
$$;

-- workstation / server: reported by the agent, else policy_platform().
ALTER TABLE agents ADD COLUMN platform text CHECK (platform IN ('workstation', 'server'));
ALTER TABLE agents ADD COLUMN category_id uuid REFERENCES device_categories(id);
-- Moved by a person (or enrolled with a category): connects don't move it back.
ALTER TABLE agents ADD COLUMN category_manual boolean NOT NULL DEFAULT false;
ALTER TABLE agents ADD COLUMN policy_pin_id uuid REFERENCES policy_sets(id) ON DELETE SET NULL;
-- policy_set_for(), kept by the trigger below and re-resolved in bulk when assignments,
-- category defaults or sets change. The default only matters while a client's agents are
-- being deleted along with its sets.
ALTER TABLE agents ADD COLUMN policy_set_id uuid NOT NULL DEFAULT '00000000-0000-4000-8001-000000000000'
    REFERENCES policy_sets(id) ON DELETE SET DEFAULT;
UPDATE agents SET platform = policy_platform(os_family, os_name);
UPDATE agents SET category_id = policy_builtin_category(os_family, platform);
ALTER TABLE agents ALTER COLUMN platform SET NOT NULL;
ALTER TABLE agents ALTER COLUMN category_id SET NOT NULL;
CREATE INDEX ON agents (policy_set_id);
CREATE INDEX ON agents (category_id);
CREATE INDEX ON agents (policy_pin_id) WHERE policy_pin_id IS NOT NULL;

-- An item's config as it applies to an agent (its set's merged config), else the item's own
-- (the agent has moved out of the item's reach: an alert it raised still needs its channels).
CREATE FUNCTION policy_config(item uuid, agent uuid) RETURNS jsonb LANGUAGE sql STABLE AS $$
    SELECT coalesce((SELECT e.config FROM policy_effective e JOIN agents a ON a.policy_set_id = e.set_id
                      WHERE a.id = agent AND e.item_id = item),
                    (SELECT i.config FROM policy_items i WHERE i.id = item))
$$;

-- Agents enrolled with this token start in this category (manual).
ALTER TABLE enrollment_tokens ADD COLUMN category_id uuid REFERENCES device_categories(id) ON DELETE SET NULL;

-- ---------------------------------------------------------------------------
-- Data: today's policies as items.
-- ---------------------------------------------------------------------------
-- Single-instance modules, from the MSP-wide rows (same ids as the old patch and sensor rows).
INSERT INTO policy_items (id, set_id, module, name, config, updated_at)
SELECT '00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8001-000000000000', 'patch', 'Patching',
       jsonb_build_object('auto_approve_severities', to_jsonb(p.auto_approve_severities), 'auto_approve_categories', to_jsonb(p.auto_approve_categories),
                          'deferral_days', p.deferral_days, 'auto_install', p.auto_install, 'reboot_policy', p.reboot_policy, 'window', NULL),
       p.updated_at
  FROM patch_policies p WHERE p.client_id IS NULL AND p.site_id IS NULL;
INSERT INTO policy_items (id, set_id, module, name, config)
SELECT '00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8001-000000000000', 'patch', 'Patching',
       '{"auto_approve_severities": [], "auto_approve_categories": ["security", "critical", "definition"], "deferral_days": 0,
         "auto_install": false, "reboot_policy": "never", "window": null}'
 WHERE NOT EXISTS (SELECT 1 FROM policy_items WHERE module = 'patch');

CREATE FUNCTION pg_temp.security_config(p security_policies) RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object('sensor_enabled', p.sensor_enabled, 'quick_scan_hours', p.quick_scan_hours, 'full_scan_days', p.full_scan_days,
                              'auto_quarantine', p.auto_quarantine, 'prevention', p.prevention, 'canaries', p.canaries,
                              'telemetry_mb', p.telemetry_mb, 'realtime', p.realtime, 'scan_on_write', p.scan_on_write,
                              'archive_depth', p.archive_depth, 'database_max_age_hours', p.database_max_age_hours)
$$;
CREATE FUNCTION pg_temp.patch_config(p patch_policies) RETURNS jsonb LANGUAGE sql AS $$
    SELECT jsonb_build_object('auto_approve_severities', to_jsonb(p.auto_approve_severities), 'auto_approve_categories', to_jsonb(p.auto_approve_categories),
                              'deferral_days', p.deferral_days, 'auto_install', p.auto_install, 'reboot_policy', p.reboot_policy, 'window', NULL)
$$;
-- The top-level fields of `target` that differ from `base`.
CREATE FUNCTION pg_temp.jsonb_diff(base jsonb, target jsonb) RETURNS jsonb LANGUAGE sql AS $$
    SELECT coalesce(jsonb_object_agg(k, v), '{}') FROM jsonb_each(target) t(k, v) WHERE base -> k IS DISTINCT FROM v
$$;

INSERT INTO policy_items (id, set_id, module, name, config, updated_at)
SELECT '00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8001-000000000000', 'security', 'Security', pg_temp.security_config(p), p.updated_at
  FROM security_policies p WHERE p.client_id IS NULL AND p.site_id IS NULL;
INSERT INTO policy_items (id, set_id, module, name, config)
SELECT '00000000-0000-4000-8000-000000000002', '00000000-0000-4000-8001-000000000000', 'security', 'Security',
       '{"sensor_enabled": false, "quick_scan_hours": 24, "full_scan_days": 7, "auto_quarantine": true, "prevention": false, "canaries": true,
         "telemetry_mb": 128, "realtime": "off", "scan_on_write": true, "archive_depth": 5, "database_max_age_hours": 72}'
 WHERE NOT EXISTS (SELECT 1 FROM policy_items WHERE module = 'security');

INSERT INTO policy_items (id, set_id, module, name, config) VALUES
    ('00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8001-000000000000', 'remote_access', 'Remote access',
     '{"desktop_enabled": true, "desktop_consent": false, "shell_enabled": true, "files_enabled": true}');
INSERT INTO policy_items (id, set_id, module, name, config)
SELECT '00000000-0000-4000-8000-000000000004', '00000000-0000-4000-8001-000000000000', 'agent', 'Agent',
       jsonb_build_object('auto_update', coalesce((SELECT auto_update_agents FROM company_settings LIMIT 1), false));

-- Alert policies keep their ids (open alerts, log events and tickets point at them). An OS
-- limit becomes the OS's set; client, site and excluded agents become the limit.
INSERT INTO policy_items (id, set_id, module, name, enabled, config, client_id, site_id, excluded_agents, created_by, created_at, updated_at)
SELECT p.id,
       CASE p.os_family WHEN 'windows' THEN '00000000-0000-4000-8001-000000000001'::uuid WHEN 'linux' THEN '00000000-0000-4000-8001-000000000002'::uuid
                        WHEN 'macos' THEN '00000000-0000-4000-8001-000000000003'::uuid ELSE '00000000-0000-4000-8001-000000000000'::uuid END,
       'alert', p.name, p.enabled,
       jsonb_build_object('kind', p.kind, 'params', p.params, 'severity', p.severity, 'channel_ids', to_jsonb(p.channel_ids),
                          'notify_resolved', p.notify_resolved, 'renotify_minutes', p.renotify_minutes, 'ticket_board_id', p.ticket_board_id,
                          'ticket_priority', p.ticket_priority, 'ticket_auto_resolve', p.ticket_auto_resolve, 'run_script_id', NULL),
       p.client_id, p.site_id, p.excluded_agents, p.created_by, p.created_at, p.updated_at
  FROM alert_policies p;

-- Scheduled scripts the same way, with their run state.
INSERT INTO policy_items (id, set_id, module, name, enabled, config, client_id, site_id, created_by, created_at, updated_at)
SELECT sc.id,
       CASE sc.os_family WHEN 'windows' THEN '00000000-0000-4000-8001-000000000001'::uuid WHEN 'linux' THEN '00000000-0000-4000-8001-000000000002'::uuid
                         WHEN 'macos' THEN '00000000-0000-4000-8001-000000000003'::uuid ELSE '00000000-0000-4000-8001-000000000000'::uuid END,
       'schedule', sc.name, sc.enabled,
       jsonb_build_object('script_id', sc.script_id, 'cron', sc.cron, 'timezone', sc.timezone, 'args', sc.args,
                          'timeout_secs', sc.timeout_secs, 'retain_days', sc.retain_days),
       sc.client_id, sc.site_id, sc.created_by, sc.created_at, sc.updated_at
  FROM schedules sc;
INSERT INTO policy_schedule_state (item_id, next_run_at, last_run_at) SELECT id, next_run_at, last_run_at FROM schedules;

-- Agents whose OS is 'other' land in Linux servers, so under the Linux set: a Linux-only
-- policy didn't cover them before and must not now.
UPDATE policy_items i SET excluded_agents = i.excluded_agents || ARRAY(SELECT a.id FROM agents a WHERE a.os_family NOT IN ('linux', 'windows', 'macos'))
 WHERE i.set_id = '00000000-0000-4000-8001-000000000002'
   AND (i.id IN (SELECT id FROM alert_policies WHERE os_family = 'linux') OR i.id IN (SELECT id FROM schedules WHERE os_family = 'linux'));

-- Clients with their own patch or sensor policy (or a site with one), or remote desktop
-- consent: a client set under each of the six leaf sets holding what differs from the MSP-wide
-- policy, assigned to the client; site policies become site sets under those, assigned to the
-- site. Old semantics were "the most specific policy applies whole"; overriding every field
-- that differs from the parent reproduces that exactly.
DO $$
DECLARE
    c record;
    si record;
    leaf record;
    cat uuid;
    cset uuid;
    sset uuid;
    g_patch jsonb := (SELECT config FROM policy_items WHERE module = 'patch');
    g_sec jsonb := (SELECT config FROM policy_items WHERE module = 'security');
    c_patch jsonb;
    c_sec jsonb;
    s_patch jsonb;
    s_sec jsonb;
    d jsonb;
BEGIN
    FOR c IN
        SELECT cl.id, cl.name, cl.desktop_consent FROM clients cl
         WHERE cl.desktop_consent
            OR EXISTS (SELECT 1 FROM patch_policies p WHERE p.client_id = cl.id)
            OR EXISTS (SELECT 1 FROM security_policies p WHERE p.client_id = cl.id)
         ORDER BY cl.name
    LOOP
        c_patch := coalesce((SELECT pg_temp.patch_config(p) FROM patch_policies p WHERE p.client_id = c.id AND p.site_id IS NULL), g_patch);
        c_sec := coalesce((SELECT pg_temp.security_config(p) FROM security_policies p WHERE p.client_id = c.id AND p.site_id IS NULL), g_sec);
        FOR leaf IN SELECT ps.id, ps.name FROM policy_sets ps JOIN device_categories dc ON dc.default_set_id = ps.id WHERE dc.builtin ORDER BY ps.id LOOP
            cat := (SELECT dc.id FROM device_categories dc WHERE dc.default_set_id = leaf.id AND dc.builtin);
            cset := gen_random_uuid();
            INSERT INTO policy_sets (id, parent_id, client_id, name) VALUES (cset, leaf.id, c.id, c.name || ' · ' || leaf.name);
            INSERT INTO policy_assignments (id, client_id, site_id, category_id, policy_set_id) VALUES (gen_random_uuid(), c.id, NULL, cat, cset);
            d := pg_temp.jsonb_diff(g_patch, c_patch);
            IF d <> '{}' THEN
                INSERT INTO policy_overrides (item_id, set_id, config) VALUES ('00000000-0000-4000-8000-000000000001', cset, d);
            END IF;
            d := pg_temp.jsonb_diff(g_sec, c_sec);
            IF d <> '{}' THEN
                INSERT INTO policy_overrides (item_id, set_id, config) VALUES ('00000000-0000-4000-8000-000000000002', cset, d);
            END IF;
            IF c.desktop_consent THEN
                INSERT INTO policy_overrides (item_id, set_id, config) VALUES ('00000000-0000-4000-8000-000000000003', cset, '{"desktop_consent": true}');
            END IF;
            FOR si IN
                SELECT s.id, s.name FROM sites s
                 WHERE s.client_id = c.id
                   AND (EXISTS (SELECT 1 FROM patch_policies p WHERE p.site_id = s.id) OR EXISTS (SELECT 1 FROM security_policies p WHERE p.site_id = s.id))
                 ORDER BY s.name
            LOOP
                s_patch := coalesce((SELECT pg_temp.patch_config(p) FROM patch_policies p WHERE p.site_id = si.id), c_patch);
                s_sec := coalesce((SELECT pg_temp.security_config(p) FROM security_policies p WHERE p.site_id = si.id), c_sec);
                sset := gen_random_uuid();
                INSERT INTO policy_sets (id, parent_id, client_id, name) VALUES (sset, cset, c.id, c.name || ' · ' || si.name || ' · ' || leaf.name);
                INSERT INTO policy_assignments (id, client_id, site_id, category_id, policy_set_id) VALUES (gen_random_uuid(), c.id, si.id, cat, sset);
                d := pg_temp.jsonb_diff(c_patch, s_patch);
                IF d <> '{}' THEN
                    INSERT INTO policy_overrides (item_id, set_id, config) VALUES ('00000000-0000-4000-8000-000000000001', sset, d);
                END IF;
                d := pg_temp.jsonb_diff(c_sec, s_sec);
                IF d <> '{}' THEN
                    INSERT INTO policy_overrides (item_id, set_id, config) VALUES ('00000000-0000-4000-8000-000000000002', sset, d);
                END IF;
            END LOOP;
        END LOOP;
    END LOOP;
END $$;

SELECT policy_rebuild(NULL);
UPDATE agents SET policy_set_id = policy_set_for(policy_pin_id, site_id, category_id);

-- From now on the trigger keeps category and set right: automatic category on enrollment and
-- each report of OS and platform (unless moved by hand), set on any change of site, category
-- or pin.
CREATE FUNCTION agents_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.platform IS NULL THEN
        NEW.platform := policy_platform(NEW.os_family, NEW.os_name);
    END IF;
    IF NOT NEW.category_manual OR NEW.category_id IS NULL THEN
        NEW.category_id := policy_builtin_category(NEW.os_family, NEW.platform);
        NEW.category_manual := false;
    END IF;
    NEW.policy_set_id := policy_set_for(NEW.policy_pin_id, NEW.site_id, NEW.category_id);
    RETURN NEW;
END $$;
CREATE TRIGGER agents_policy BEFORE INSERT OR UPDATE OF site_id, os_family, os_name, platform, category_id, category_manual, policy_pin_id
    ON agents FOR EACH ROW EXECUTE FUNCTION agents_policy();

-- ---------------------------------------------------------------------------
-- Re-point what referenced the old tables, then drop them.
-- ---------------------------------------------------------------------------
ALTER TABLE alerts DROP CONSTRAINT alerts_policy_id_fkey;
ALTER TABLE alerts ADD CONSTRAINT alerts_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES policy_items(id) ON DELETE SET NULL;
ALTER TABLE log_events DROP CONSTRAINT log_events_policy_id_fkey;
ALTER TABLE log_events ADD CONSTRAINT log_events_policy_id_fkey FOREIGN KEY (policy_id) REFERENCES policy_items(id) ON DELETE SET NULL;
ALTER TABLE tickets DROP CONSTRAINT tickets_alert_policy_id_fkey;
ALTER TABLE tickets ADD CONSTRAINT tickets_alert_policy_id_fkey FOREIGN KEY (alert_policy_id) REFERENCES policy_items(id) ON DELETE SET NULL;
ALTER TABLE jobs DROP CONSTRAINT jobs_schedule_id_fkey;
ALTER TABLE jobs ADD CONSTRAINT jobs_schedule_id_fkey FOREIGN KEY (schedule_id) REFERENCES policy_items(id) ON DELETE SET NULL;

-- The job an alert item's run_script_id started when the alert opened.
ALTER TABLE alerts ADD COLUMN script_job_id uuid REFERENCES jobs(id) ON DELETE SET NULL;

DROP FUNCTION pg_temp.security_config(security_policies);
DROP FUNCTION pg_temp.patch_config(patch_policies);
DROP VIEW agent_patch_policy;
DROP TABLE alert_policies;
DROP TABLE patch_policies;
DROP TABLE security_policies;
DROP TABLE schedules;
ALTER TABLE clients DROP COLUMN desktop_consent;
ALTER TABLE company_settings DROP COLUMN auto_update_agents;

-- ---------------------------------------------------------------------------
-- What applies to each agent.
-- ---------------------------------------------------------------------------
-- Every item reaching the agent's set whose limit includes the agent (enabled or not).
CREATE VIEW agent_policy AS
SELECT a.id AS agent_id, i.id AS item_id, i.module, i.name, e.enabled, e.config, i.set_id AS origin_set_id,
       i.client_id, i.site_id, i.excluded_agents
  FROM agents a
  JOIN sites s ON s.id = a.site_id
  JOIN policy_effective e ON e.set_id = a.policy_set_id
  JOIN policy_items i ON i.id = e.item_id
 WHERE (i.client_id IS NULL OR i.client_id = s.client_id) AND (i.site_id IS NULL OR i.site_id = a.site_id)
   AND NOT (a.id = ANY(i.excluded_agents));

-- The patch policy each agent runs with, and the set it comes from (`source`). The window is
-- the policy's own when it has one (tz 'site': the site's zone), else the site's.
CREATE VIEW agent_patch_policy AS
SELECT a.id AS agent_id, e.item_id AS id, a.policy_set_id AS set_id, ps.name AS source,
       ARRAY(SELECT jsonb_array_elements_text(e.config -> 'auto_approve_severities')) AS auto_approve_severities,
       ARRAY(SELECT jsonb_array_elements_text(e.config -> 'auto_approve_categories')) AS auto_approve_categories,
       (e.config ->> 'deferral_days')::int AS deferral_days,
       (e.config ->> 'auto_install')::boolean AS auto_install,
       e.config ->> 'reboot_policy' AS reboot_policy,
       jsonb_typeof(e.config -> 'window') = 'object' AS own_window,
       CASE WHEN jsonb_typeof(e.config -> 'window') = 'object'
            THEN ARRAY(SELECT d::smallint FROM jsonb_array_elements_text(e.config -> 'window' -> 'days') d) ELSE s.maint_days END AS maint_days,
       CASE WHEN jsonb_typeof(e.config -> 'window') = 'object' THEN (e.config -> 'window' ->> 'start')::time ELSE s.maint_start END AS maint_start,
       CASE WHEN jsonb_typeof(e.config -> 'window') = 'object' THEN (e.config -> 'window' ->> 'minutes')::int ELSE s.maint_minutes END AS maint_minutes,
       CASE WHEN jsonb_typeof(e.config -> 'window') = 'object' AND e.config -> 'window' ->> 'tz' <> 'site'
            THEN e.config -> 'window' ->> 'tz' ELSE s.maint_tz END AS maint_tz
  FROM agents a
  JOIN sites s ON s.id = a.site_id
  JOIN policy_sets ps ON ps.id = a.policy_set_id
  JOIN policy_effective e ON e.set_id = a.policy_set_id AND e.item_id = '00000000-0000-4000-8000-000000000001';

-- The sensor policy each agent runs with.
CREATE VIEW agent_security_policy AS
SELECT a.id AS agent_id, a.policy_set_id AS set_id, ps.name AS source,
       (e.config ->> 'sensor_enabled')::boolean AS sensor_enabled,
       (e.config ->> 'quick_scan_hours')::int AS quick_scan_hours,
       (e.config ->> 'full_scan_days')::int AS full_scan_days,
       (e.config ->> 'auto_quarantine')::boolean AS auto_quarantine,
       (e.config ->> 'prevention')::boolean AS prevention,
       (e.config ->> 'canaries')::boolean AS canaries,
       (e.config ->> 'telemetry_mb')::int AS telemetry_mb,
       e.config ->> 'realtime' AS realtime,
       (e.config ->> 'scan_on_write')::boolean AS scan_on_write,
       (e.config ->> 'archive_depth')::int AS archive_depth,
       (e.config ->> 'database_max_age_hours')::int AS database_max_age_hours
  FROM agents a
  JOIN policy_sets ps ON ps.id = a.policy_set_id
  JOIN policy_effective e ON e.set_id = a.policy_set_id AND e.item_id = '00000000-0000-4000-8000-000000000002';
