-- Stored columns for agent search and agent health (docs/research/load-test-2026-11.md: at 10,000
-- agents the search scanned every inventory's JSON, ~0.8 s, and the dashboard worked health out
-- for every agent on every request, ~0.3 s, refetched on every alert, job and online event).
--
-- Search: the IP addresses and logged-in users move out of the inventory JSON into a small table
-- with trigram indexes (so a prefix or substring match is an index lookup), kept in step by a trigger
-- on `agents.inventory`; hostname and OS name get trigram indexes of their own.
-- Health: the inputs to an agent's health, and the rank worked out from them, are stored on the
-- agent and kept current by triggers on the tables they come from (alerts, jobs, patches) and on
-- the agent row itself (heartbeat, update state, reboot flag). What no trigger sees is time
-- passing (a failed job ages past 24 hours, an update ages past a week); the server's
-- housekeeping calls `refresh_agent_health()` every few minutes for those, and as a safety net.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ---- search -------------------------------------------------------------------------------------------------

CREATE TABLE agent_search_terms (
    agent_id  uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    -- 'ip': an address of a network interface; 'user': a logged-in user.
    kind      text NOT NULL CHECK (kind IN ('ip', 'user')),
    term      text NOT NULL,
    PRIMARY KEY (agent_id, kind, term)
);
CREATE INDEX agent_search_ip ON agent_search_terms USING gin (term gin_trgm_ops) WHERE kind = 'ip';
CREATE INDEX agent_search_user ON agent_search_terms USING gin (term gin_trgm_ops) WHERE kind = 'user';
CREATE INDEX agents_hostname_trgm ON agents USING gin (hostname gin_trgm_ops);
CREATE INDEX agents_os_name_trgm ON agents USING gin (os_name gin_trgm_ops);

-- The terms of an inventory document: its interfaces' addresses and its logged-in users.
CREATE FUNCTION agent_inventory_terms(inv jsonb) RETURNS TABLE (kind text, term text) LANGUAGE sql IMMUTABLE AS $$
    SELECT DISTINCT 'ip', left(ip, 512)
      FROM jsonb_array_elements(CASE WHEN jsonb_typeof(inv->'network') = 'array' THEN inv->'network' ELSE '[]'::jsonb END) nic,
           jsonb_array_elements_text(CASE WHEN jsonb_typeof(nic->'addrs') = 'array' THEN nic->'addrs' ELSE '[]'::jsonb END) ip
    UNION
    SELECT DISTINCT 'user', left(lu, 512)
      FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(inv->'logged_in_users') = 'array' THEN inv->'logged_in_users' ELSE '[]'::jsonb END) lu
$$;

-- Replaces an agent's terms with those in `inv`, leaving rows that stay untouched.
CREATE FUNCTION agent_search_terms_refresh(aid uuid, inv jsonb) RETURNS void LANGUAGE sql AS $$
    DELETE FROM agent_search_terms t
     WHERE t.agent_id = aid AND NOT EXISTS (SELECT 1 FROM agent_inventory_terms(inv) n WHERE n.kind = t.kind AND n.term = t.term);
    INSERT INTO agent_search_terms (agent_id, kind, term) SELECT aid, kind, term FROM agent_inventory_terms(inv) ON CONFLICT DO NOTHING;
$$;

CREATE FUNCTION agents_search_terms_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.inventory IS NOT DISTINCT FROM OLD.inventory THEN
        RETURN NULL;
    END IF;
    IF NEW.inventory IS NOT NULL OR TG_OP = 'UPDATE' THEN
        PERFORM agent_search_terms_refresh(NEW.id, NEW.inventory);
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER agents_search_terms AFTER INSERT OR UPDATE OF inventory ON agents
    FOR EACH ROW EXECUTE FUNCTION agents_search_terms_sync();

SELECT agent_search_terms_refresh(id, inventory) FROM agents WHERE inventory IS NOT NULL;

-- ---- health -------------------------------------------------------------------------------------------------

ALTER TABLE agents
    -- 0 healthy, 1 unknown (never reported), 2 needs attention, 3 unhealthy: see `agent_health_rank`.
    ADD COLUMN health_rank      smallint NOT NULL DEFAULT 1,
    -- Fullest disk, in percent, from the last heartbeat (0 if none).
    ADD COLUMN disk_max_pct     float8 NOT NULL DEFAULT 0,
    -- Unresolved alerts (all of them), and whether any that isn't held back by a maintenance
    -- window or snooze is critical / a warning.
    ADD COLUMN open_alerts      integer NOT NULL DEFAULT 0,
    ADD COLUMN alert_critical   boolean NOT NULL DEFAULT false,
    ADD COLUMN alert_warning    boolean NOT NULL DEFAULT false,
    -- Jobs that failed, errored, timed out or were lost in the last 24 hours.
    ADD COLUMN failed_jobs_24h  integer NOT NULL DEFAULT 0,
    -- Security or critical updates missing for over a week, not declined; updates whose last
    -- install failed, not declined since.
    ADD COLUMN patches_overdue  integer NOT NULL DEFAULT 0,
    ADD COLUMN patches_failed   integer NOT NULL DEFAULT 0;

-- The rank, from the stored inputs and the agent's own fields. Online/offline is separate: a
-- workstation that is switched off isn't unhealthy (unless an offline alert policy says so).
-- Open critical alerts make an agent unhealthy, warnings make it need attention.
CREATE FUNCTION agent_health_rank(a agents) RETURNS smallint LANGUAGE sql STABLE AS $$
    SELECT (CASE
        WHEN a.alert_critical THEN 3
        WHEN a.last_metrics IS NULL THEN 1
        WHEN a.disk_max_pct >= 95 THEN 3
        WHEN a.disk_max_pct >= 90 OR a.alert_warning OR a.failed_jobs_24h > 0
             OR (a.update_state IN ('failed', 'rolled_back') AND a.update_at > now() - interval '7 days')
             OR a.patches_failed > 0 OR a.patches_overdue > 0
             OR (a.reboot_pending AND a.reboot_pending_since < now() - interval '24 hours')
        THEN 2 ELSE 0 END)::smallint
$$;

-- Runs before the row is written whenever one of the inputs is set (every heartbeat sets
-- `last_metrics`; the refreshes below set the counters).
CREATE FUNCTION agents_health_row() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.disk_max_pct := coalesce(
        (SELECT max(100 * (1 - (d->>'available')::float8 / (d->>'total')::float8))
           FROM jsonb_array_elements(CASE WHEN jsonb_typeof(NEW.last_metrics->'disks') = 'array' THEN NEW.last_metrics->'disks' ELSE '[]'::jsonb END) d
          WHERE (d->>'total')::float8 > 0), 0);
    NEW.health_rank := agent_health_rank(NEW);
    RETURN NEW;
END $$;
CREATE TRIGGER agents_health BEFORE INSERT OR UPDATE OF last_metrics, update_state, update_at, reboot_pending, reboot_pending_since,
        alert_critical, alert_warning, failed_jobs_24h, patches_overdue, patches_failed
    ON agents FOR EACH ROW EXECUTE FUNCTION agents_health_row();

-- Recounts from the tables. `ids` NULL = every agent. Writes only what changed, so a refresh
-- that finds nothing new doesn't rewrite the agent rows.
CREATE FUNCTION refresh_agent_alerts(ids uuid[]) RETURNS void LANGUAGE sql AS $$
    UPDATE agents a SET open_alerts = x.n, alert_critical = x.c, alert_warning = x.w
      FROM (SELECT g.id, count(al.id)::int AS n,
                   coalesce(bool_or(al.severity = 'critical' AND NOT al.suppressed), false) AS c,
                   coalesce(bool_or(al.severity = 'warning' AND NOT al.suppressed), false) AS w
              FROM agents g LEFT JOIN alerts al ON al.agent_id = g.id AND al.resolved_at IS NULL
             WHERE ids IS NULL OR g.id = ANY(ids)
             GROUP BY g.id) x
     WHERE a.id = x.id AND (a.open_alerts, a.alert_critical, a.alert_warning) IS DISTINCT FROM (x.n, x.c, x.w)
$$;
CREATE FUNCTION refresh_agent_jobs(ids uuid[]) RETURNS void LANGUAGE sql AS $$
    UPDATE agents a SET failed_jobs_24h = x.n
      FROM (SELECT g.id, count(j.id)::int AS n
              FROM agents g LEFT JOIN jobs j ON j.agent_id = g.id AND j.created_at > now() - interval '24 hours'
                                             AND j.status IN ('failed', 'error', 'timed_out', 'lost')
             WHERE ids IS NULL OR g.id = ANY(ids)
             GROUP BY g.id) x
     WHERE a.id = x.id AND a.failed_jobs_24h <> x.n
$$;
CREATE FUNCTION refresh_agent_patches(ids uuid[]) RETURNS void LANGUAGE sql AS $$
    UPDATE agents a SET patches_overdue = x.o, patches_failed = x.f
      FROM (SELECT g.id,
                   count(p.agent_id) FILTER (WHERE (p.category IN ('security', 'critical') OR p.severity = 'critical')
                                                   AND p.first_seen_at < now() - interval '7 days')::int AS o,
                   count(p.agent_id) FILTER (WHERE p.state = 'failed')::int AS f
              FROM agents g LEFT JOIN patches p ON p.agent_id = g.id AND p.state <> 'installed' AND p.approval <> 'declined'
             WHERE ids IS NULL OR g.id = ANY(ids)
             GROUP BY g.id) x
     WHERE a.id = x.id AND (a.patches_overdue, a.patches_failed) IS DISTINCT FROM (x.o, x.f)
$$;
-- Everything, then the rank again for what only time changed (a reboot pending for a day, an
-- update failure older than a week), which no counter shows.
CREATE FUNCTION refresh_agent_health(ids uuid[] DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    PERFORM refresh_agent_alerts(ids);
    PERFORM refresh_agent_jobs(ids);
    PERFORM refresh_agent_patches(ids);
    UPDATE agents a SET health_rank = agent_health_rank(a)
     WHERE (ids IS NULL OR a.id = ANY(ids)) AND a.health_rank <> agent_health_rank(a);
END $$;

-- Alerts: opened, resolved, held back or released, re-rated.
CREATE FUNCTION alerts_health_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.resolved_at IS NULL THEN PERFORM refresh_agent_alerts(ARRAY[NEW.agent_id]); END IF;
    ELSIF TG_OP = 'DELETE' THEN
        IF OLD.resolved_at IS NULL THEN PERFORM refresh_agent_alerts(ARRAY[OLD.agent_id]); END IF;
    ELSIF (OLD.resolved_at IS NULL) IS DISTINCT FROM (NEW.resolved_at IS NULL) OR OLD.suppressed IS DISTINCT FROM NEW.suppressed
          OR OLD.severity IS DISTINCT FROM NEW.severity OR OLD.agent_id IS DISTINCT FROM NEW.agent_id THEN
        PERFORM refresh_agent_alerts(ARRAY[NEW.agent_id, OLD.agent_id]);
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER alerts_health AFTER INSERT OR UPDATE OF resolved_at, suppressed, severity, agent_id OR DELETE ON alerts
    FOR EACH ROW EXECUTE FUNCTION alerts_health_sync();

-- Jobs: only a failure status counts, so the queued/sent/succeeded rows (almost all of them,
-- and bulk runs insert hundreds at once) never fire the trigger.
CREATE FUNCTION jobs_health_sync() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        PERFORM refresh_agent_jobs(ARRAY[NEW.agent_id]);
    ELSIF TG_OP = 'DELETE' THEN
        IF OLD.created_at > now() - interval '24 hours' THEN PERFORM refresh_agent_jobs(ARRAY[OLD.agent_id]); END IF;
    ELSE
        PERFORM refresh_agent_jobs(ARRAY[NEW.agent_id, OLD.agent_id]);
    END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER jobs_health_insert AFTER INSERT ON jobs
    FOR EACH ROW WHEN (NEW.status IN ('failed', 'error', 'timed_out', 'lost')) EXECUTE FUNCTION jobs_health_sync();
CREATE TRIGGER jobs_health_update AFTER UPDATE OF status, agent_id ON jobs
    FOR EACH ROW WHEN ((OLD.status IN ('failed', 'error', 'timed_out', 'lost')) IS DISTINCT FROM (NEW.status IN ('failed', 'error', 'timed_out', 'lost'))
                       OR OLD.agent_id IS DISTINCT FROM NEW.agent_id) EXECUTE FUNCTION jobs_health_sync();
CREATE TRIGGER jobs_health_delete AFTER DELETE ON jobs
    FOR EACH ROW WHEN (OLD.status IN ('failed', 'error', 'timed_out', 'lost')) EXECUTE FUNCTION jobs_health_sync();

-- Patches: a scan upserts a dozen rows in one statement and a policy can touch thousands, so these
-- run once per statement, for the agents whose rows changed in a way that counts.
CREATE FUNCTION patches_health_sync() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ids uuid[];
BEGIN
    IF TG_OP = 'INSERT' THEN
        ids := ARRAY(SELECT DISTINCT agent_id FROM new_rows WHERE state <> 'installed');
    ELSIF TG_OP = 'DELETE' THEN
        ids := ARRAY(SELECT DISTINCT agent_id FROM old_rows WHERE state <> 'installed');
    ELSE
        ids := ARRAY(SELECT DISTINCT n.agent_id FROM new_rows n JOIN old_rows o ON o.agent_id = n.agent_id AND o.update_id = n.update_id
                      WHERE (o.state, o.approval, o.category, o.severity, o.first_seen_at)
                            IS DISTINCT FROM (n.state, n.approval, n.category, n.severity, n.first_seen_at));
    END IF;
    IF cardinality(ids) > 0 THEN PERFORM refresh_agent_patches(ids); END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER patches_health_insert AFTER INSERT ON patches REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION patches_health_sync();
CREATE TRIGGER patches_health_update AFTER UPDATE ON patches REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION patches_health_sync();
CREATE TRIGGER patches_health_delete AFTER DELETE ON patches REFERENCING OLD TABLE AS old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION patches_health_sync();

-- Existing agents: the disk figure and the counters, then the rank.
UPDATE agents SET last_metrics = last_metrics WHERE last_metrics IS NOT NULL;
SELECT refresh_agent_health();
