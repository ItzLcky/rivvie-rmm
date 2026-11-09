-- Phase 5: patch management.

-- Optional features the agent build supports (from its Auth message), and its last patch scan.
ALTER TABLE agents ADD COLUMN capabilities            text[] NOT NULL DEFAULT '{}';
ALTER TABLE agents ADD COLUMN patch_provider          text;
ALTER TABLE agents ADD COLUMN patch_all_or_nothing    boolean NOT NULL DEFAULT false;
ALTER TABLE agents ADD COLUMN patch_scan_requested_at timestamptz;
ALTER TABLE agents ADD COLUMN patch_scanned_at        timestamptz;
ALTER TABLE agents ADD COLUMN patch_scan_error        text;
ALTER TABLE agents ADD COLUMN reboot_pending          boolean NOT NULL DEFAULT false;

-- Maintenance window per site: automatic installs only start inside it. No days = no window,
-- so automatic installs may start at any time.
ALTER TABLE sites ADD COLUMN maint_days    smallint[];   -- 0 = Sunday ... 6 = Saturday
ALTER TABLE sites ADD COLUMN maint_start   time;
ALTER TABLE sites ADD COLUMN maint_minutes integer CHECK (maint_minutes BETWEEN 15 AND 1440);
ALTER TABLE sites ADD COLUMN maint_tz      text NOT NULL DEFAULT 'UTC';

-- Whether `at` falls in a window that opens at `start` local time on each of `days` and lasts
-- `minutes`. Yesterday's window counts too, for windows that run past midnight.
CREATE FUNCTION in_maintenance_window(days smallint[], start time, minutes integer, tz text, at timestamptz)
RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT days IS NULL OR cardinality(days) = 0 OR EXISTS (
        SELECT 1 FROM generate_series(0, 1) d
         WHERE extract(dow FROM (at AT TIME ZONE tz)::date - d)::smallint = ANY (days)
           AND (at AT TIME ZONE tz) >= ((at AT TIME ZONE tz)::date - d) + start
           AND (at AT TIME ZONE tz) <  ((at AT TIME ZONE tz)::date - d) + start + make_interval(mins => minutes))
$$;

-- When the next window opens after `at` (NULL without a window).
CREATE FUNCTION next_maintenance_window(days smallint[], start time, tz text, at timestamptz)
RETURNS timestamptz LANGUAGE sql STABLE AS $$
    SELECT min((((at AT TIME ZONE tz)::date + d) + start) AT TIME ZONE tz)
      FROM generate_series(0, 7) d
     WHERE cardinality(days) > 0
       AND extract(dow FROM (at AT TIME ZONE tz)::date + d)::smallint = ANY (days)
       AND (((at AT TIME ZONE tz)::date + d) + start) AT TIME ZONE tz > at
$$;

-- What to approve and install automatically. One MSP-wide policy (client and site NULL),
-- optionally overridden per client and per site; the most specific one applies, whole.
CREATE TABLE patch_policies (
    id                       uuid PRIMARY KEY,
    client_id                uuid REFERENCES clients(id) ON DELETE CASCADE,
    site_id                  uuid REFERENCES sites(id) ON DELETE CASCADE,
    -- Approve an update automatically when its severity or its category is listed.
    auto_approve_severities  text[] NOT NULL DEFAULT '{}',
    auto_approve_categories  text[] NOT NULL DEFAULT '{}',
    -- Automatically approved updates wait this long after first being seen before installing.
    deferral_days            integer NOT NULL DEFAULT 0 CHECK (deferral_days BETWEEN 0 AND 365),
    -- Install approved updates during the site's maintenance window.
    auto_install             boolean NOT NULL DEFAULT false,
    reboot_policy            text NOT NULL DEFAULT 'never' CHECK (reboot_policy IN ('never', 'if_required', 'always')),
    updated_by               uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at               timestamptz NOT NULL DEFAULT now(),
    CHECK (site_id IS NULL OR client_id IS NOT NULL)
);
CREATE UNIQUE INDEX patch_policies_scope ON patch_policies (client_id, site_id) NULLS NOT DISTINCT;

-- Conservative default: approve security, critical and definition updates, install nothing
-- until someone turns automatic installs on.
INSERT INTO patch_policies (id, auto_approve_categories)
VALUES ('00000000-0000-4000-8000-000000000001', '{security,critical,definition}');

-- The policy that applies to each agent, and where it comes from.
CREATE VIEW agent_patch_policy AS
SELECT a.id AS agent_id, pol.*,
       CASE WHEN pol.site_id IS NOT NULL THEN 'site' WHEN pol.client_id IS NOT NULL THEN 'client' ELSE 'global' END AS source
  FROM agents a
  JOIN sites s ON s.id = a.site_id
  JOIN LATERAL (
        SELECT p.* FROM patch_policies p
         WHERE p.site_id = s.id
            OR (p.client_id = s.client_id AND p.site_id IS NULL)
            OR (p.client_id IS NULL AND p.site_id IS NULL)
         ORDER BY (p.site_id IS NOT NULL) DESC, (p.client_id IS NOT NULL) DESC
         LIMIT 1) pol ON true;

-- One row per agent and update, from the agent's scans.
CREATE TABLE patches (
    agent_id         uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    -- Windows Update id, package name (name.arch on dnf), or softwareupdate label.
    update_id        text NOT NULL,
    title            text NOT NULL,
    kb               text,
    severity         text,
    category         text NOT NULL,
    size             bigint,
    requires_reboot  boolean NOT NULL DEFAULT false,
    version          text,
    current_version  text,
    -- missing: offered by the last scan; installing: in a run; installed: gone from the scans
    -- (by us or otherwise); failed: the last install of it failed.
    state            text NOT NULL DEFAULT 'missing' CHECK (state IN ('missing', 'installing', 'installed', 'failed')),
    approval         text NOT NULL DEFAULT 'pending' CHECK (approval IN ('pending', 'approved', 'declined')),
    -- Decided by a person (kept when policies change), rather than by the policy.
    approval_manual  boolean NOT NULL DEFAULT false,
    approved_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    approved_at      timestamptz,
    first_seen_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    installed_at     timestamptz,
    fail_count       integer NOT NULL DEFAULT 0,
    last_error       text,
    PRIMARY KEY (agent_id, update_id)
);
CREATE INDEX patches_update ON patches (update_id);
CREATE INDEX patches_open ON patches (agent_id) WHERE state <> 'installed';

-- Installs: one per agent each time updates are pushed to it.
CREATE TABLE patch_runs (
    id               uuid PRIMARY KEY,
    agent_id         uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    update_ids       text[] NOT NULL,
    reboot_policy    text NOT NULL CHECK (reboot_policy IN ('never', 'if_required', 'always')),
    trigger          text NOT NULL CHECK (trigger IN ('manual', 'policy')),
    created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    status           text NOT NULL DEFAULT 'queued'
                     CHECK (status IN ('queued', 'sent', 'succeeded', 'partial', 'failed', 'lost', 'expired', 'cancelled')),
    stage            text,
    progress         text,
    percent          smallint,
    error            text,
    results          jsonb NOT NULL DEFAULT '[]',
    reboot_required  boolean NOT NULL DEFAULT false,
    rebooting        boolean NOT NULL DEFAULT false,
    output           text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    sent_at          timestamptz,
    finished_at      timestamptz,
    duration_ms      bigint
);
CREATE INDEX patch_runs_agent ON patch_runs (agent_id, created_at DESC);
CREATE INDEX patch_runs_created ON patch_runs (created_at DESC, id DESC);
CREATE INDEX patch_runs_open ON patch_runs (agent_id) WHERE status IN ('queued', 'sent');
