-- Network discovery and SNMP monitoring (docs/design/network.md).
--
-- A site's designated agent scans its network for devices and reads switches, firewalls and
-- printers over SNMP. Discovered hosts are matched to the agents we manage (by MAC, else by IP
-- within the site); the rest are the "unmanaged devices". Devices worth watching become
-- `net_devices`, polled through the designated agent, with samples and hourly rollups like an
-- agent's own metrics. Their alerts are ordinary alerts (`alerts.device_id`), opened by the
-- alert items of the designated agent's policy set.

-- SNMP credentials, per client. The secret is JSON, sealed with RMM_DATA_KEY when it is set
-- (crypto::store): {"community": "..."} for v2c, {"auth_secret": "...", "priv_secret": "..."} for v3.
CREATE TABLE net_credentials (
    id             uuid PRIMARY KEY,
    client_id      uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name           text NOT NULL,
    version        text NOT NULL CHECK (version IN ('v2c', 'v3')),
    username       text NOT NULL DEFAULT '',
    auth_proto     text CHECK (auth_proto IN ('md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512')),
    priv_proto     text CHECK (priv_proto IN ('des', 'aes128')),
    context        text NOT NULL DEFAULT '',
    secret         bytea NOT NULL,
    secret_sealed  boolean NOT NULL DEFAULT false,
    created_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (client_id, name)
);

-- Per site: which agent does the work, and what it scans.
CREATE TABLE site_network (
    site_id          uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    agent_id         uuid REFERENCES agents(id) ON DELETE SET NULL,
    -- CIDR blocks; empty means the agent's own subnets.
    subnets          text[] NOT NULL DEFAULT '{}',
    -- Scan again this often; 0 means only when asked.
    discovery_hours  integer NOT NULL DEFAULT 0 CHECK (discovery_hours BETWEEN 0 AND 720),
    -- Credentials tried on every live host, in order.
    credential_ids   uuid[] NOT NULL DEFAULT '{}',
    -- How often monitored devices are read, unless a device says otherwise.
    poll_secs        integer NOT NULL DEFAULT 300 CHECK (poll_secs BETWEEN 60 AND 3600),
    updated_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE discovery_scans (
    id            uuid PRIMARY KEY,
    site_id       uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    agent_id      uuid REFERENCES agents(id) ON DELETE SET NULL,
    status        text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done', 'failed')),
    subnets       text[] NOT NULL DEFAULT '{}',
    scanned       integer NOT NULL DEFAULT 0,
    found         integer NOT NULL DEFAULT 0,
    -- Hosts never seen before.
    new_hosts     integer NOT NULL DEFAULT 0,
    error         text,
    requested_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    finished_at   timestamptz
);
CREATE INDEX ON discovery_scans (site_id, created_at DESC);

-- Everything scans have found. A host is known by its MAC address when the agent could see
-- one, else by its IP address.
CREATE TABLE discovered_devices (
    id              uuid PRIMARY KEY,
    site_id         uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    ip              text NOT NULL,
    mac             text,
    hostname        text,
    mdns_name       text,
    vendor          text,
    sys_name        text,
    sys_descr       text,
    sys_object_id   text,
    sys_location    text,
    -- The credentials that worked on it.
    credential_id   uuid REFERENCES net_credentials(id) ON DELETE SET NULL,
    open_ports      integer[] NOT NULL DEFAULT '{}',
    methods         text[] NOT NULL DEFAULT '{}',
    -- Our guess: switch, router, firewall, printer, ap, ups, nas, server, windows, linux, other.
    kind            text NOT NULL DEFAULT 'other',
    -- unmanaged: needs a look; ignored: not interesting; known: accepted without an agent.
    status          text NOT NULL DEFAULT 'unmanaged' CHECK (status IN ('unmanaged', 'ignored', 'known')),
    note            text NOT NULL DEFAULT '',
    -- The agent that is this host (matched on MAC, else IP in the same site).
    agent_id        uuid REFERENCES agents(id) ON DELETE SET NULL,
    online          boolean NOT NULL DEFAULT true,
    rtt_ms          integer,
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    last_scan_id    uuid REFERENCES discovery_scans(id) ON DELETE SET NULL
);
CREATE UNIQUE INDEX discovered_by_mac ON discovered_devices (site_id, mac) WHERE mac IS NOT NULL;
CREATE UNIQUE INDEX discovered_by_ip ON discovered_devices (site_id, ip) WHERE mac IS NULL;
CREATE INDEX ON discovered_devices (site_id, last_seen_at DESC);
CREATE INDEX ON discovered_devices (agent_id) WHERE agent_id IS NOT NULL;

-- Devices read over SNMP.
CREATE TABLE net_devices (
    id              uuid PRIMARY KEY,
    site_id         uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    name            text NOT NULL,
    host            text NOT NULL,
    port            integer NOT NULL DEFAULT 161 CHECK (port BETWEEN 1 AND 65535),
    credential_id   uuid NOT NULL REFERENCES net_credentials(id) ON DELETE RESTRICT,
    kind            text NOT NULL DEFAULT 'other',
    enabled         boolean NOT NULL DEFAULT true,
    -- NULL: the site's interval.
    poll_secs       integer CHECK (poll_secs BETWEEN 60 AND 3600),
    sys_descr       text,
    sys_name        text,
    sys_object_id   text,
    sys_location    text,
    vendor          text,
    mac             text,
    -- unknown: never read, or the designated agent is offline; up; down.
    state           text NOT NULL DEFAULT 'unknown' CHECK (state IN ('unknown', 'up', 'down')),
    state_since     timestamptz NOT NULL DEFAULT now(),
    last_poll_at    timestamptz,
    last_ok_at      timestamptz,
    last_error      text,
    rtt_ms          integer,
    uptime_secs     bigint,
    cpu_percent     real,
    mem_used        bigint,
    mem_total       bigint,
    -- [{descr, kind, total, used}] and [{index, description, class, kind, percent}], as last read.
    storage         jsonb NOT NULL DEFAULT '[]',
    supplies        jsonb NOT NULL DEFAULT '[]',
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (site_id, host, port)
);
CREATE INDEX ON net_devices (site_id);
ALTER TABLE discovered_devices ADD COLUMN net_device_id uuid REFERENCES net_devices(id) ON DELETE SET NULL;

-- Interfaces: the current state of each, and the counters the next sample's rate is worked out from.
CREATE TABLE net_interfaces (
    device_id       uuid NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    if_index        integer NOT NULL,
    name            text NOT NULL,
    descr           text NOT NULL DEFAULT '',
    alias           text NOT NULL DEFAULT '',
    if_type         integer NOT NULL DEFAULT 0,
    speed_bps       bigint NOT NULL DEFAULT 0,
    admin_status    smallint NOT NULL DEFAULT 1,
    oper_status     smallint NOT NULL DEFAULT 1,
    status_since    timestamptz NOT NULL DEFAULT now(),
    -- Samples and "interface down" alerts are kept for monitored interfaces only. An interface
    -- becomes monitored when it is first seen up, so unused ports don't alert or fill the database.
    monitored       boolean NOT NULL DEFAULT false,
    -- The user chose; the automatic rule leaves it alone.
    monitored_manual boolean NOT NULL DEFAULT false,
    in_bps          bigint,
    out_bps         bigint,
    util_pct        real,
    in_errors       bigint NOT NULL DEFAULT 0,
    out_errors      bigint NOT NULL DEFAULT 0,
    in_discards     bigint NOT NULL DEFAULT 0,
    out_discards    bigint NOT NULL DEFAULT 0,
    last_in_octets  bigint,
    last_out_octets bigint,
    last_hc         boolean NOT NULL DEFAULT false,
    last_at         timestamptz,
    last_uptime     bigint,
    PRIMARY KEY (device_id, if_index)
);

CREATE TABLE net_device_metrics (
    device_id    uuid NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    ts           timestamptz NOT NULL,
    reachable    boolean NOT NULL,
    rtt_ms       integer,
    uptime_secs  bigint,
    cpu_percent  real,
    mem_used     bigint,
    mem_total    bigint,
    PRIMARY KEY (device_id, ts)
);

CREATE TABLE net_interface_metrics (
    device_id    uuid NOT NULL,
    if_index     integer NOT NULL,
    ts           timestamptz NOT NULL,
    oper_status  smallint NOT NULL,
    in_bps       bigint,
    out_bps      bigint,
    util_pct     real,
    in_errors    bigint NOT NULL DEFAULT 0,
    out_errors   bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, if_index, ts),
    FOREIGN KEY (device_id, if_index) REFERENCES net_interfaces(device_id, if_index) ON DELETE CASCADE
);

-- Hourly rollups, like agent_metrics_hourly.
CREATE TABLE net_device_metrics_hourly (
    device_id    uuid NOT NULL REFERENCES net_devices(id) ON DELETE CASCADE,
    hour         timestamptz NOT NULL,
    samples      integer NOT NULL,
    reachable    integer NOT NULL,
    rtt_avg      real,
    rtt_max      integer,
    cpu_avg      real,
    cpu_max      real,
    mem_used_avg bigint,
    mem_total    bigint,
    PRIMARY KEY (device_id, hour)
);
CREATE INDEX ON net_device_metrics_hourly (hour);

CREATE TABLE net_interface_metrics_hourly (
    device_id    uuid NOT NULL,
    if_index     integer NOT NULL,
    hour         timestamptz NOT NULL,
    samples      integer NOT NULL,
    up_samples   integer NOT NULL,
    in_bps_avg   bigint,
    in_bps_max   bigint,
    out_bps_avg  bigint,
    out_bps_max  bigint,
    util_max     real,
    errors       bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, if_index, hour),
    FOREIGN KEY (device_id, if_index) REFERENCES net_interfaces(device_id, if_index) ON DELETE CASCADE
);
CREATE INDEX ON net_interface_metrics_hourly (hour);

-- Alerts about a device. `agent_id` stays the designated agent that reads it (the alert engine,
-- notifications and tickets all work from an agent and its policy set).
ALTER TABLE alerts ADD COLUMN device_id uuid REFERENCES net_devices(id) ON DELETE CASCADE;
CREATE INDEX alerts_device ON alerts (device_id, opened_at DESC) WHERE device_id IS NOT NULL;

-- A switch going down is not the designated agent's health: only the agent's own alerts count
-- (migration 0026's counters, with the one condition added).
CREATE OR REPLACE FUNCTION refresh_agent_alerts(ids uuid[]) RETURNS void LANGUAGE sql AS $$
    UPDATE agents a SET open_alerts = x.n, alert_critical = x.c, alert_warning = x.w
      FROM (SELECT g.id, count(al.id)::int AS n,
                   coalesce(bool_or(al.severity = 'critical' AND NOT al.suppressed), false) AS c,
                   coalesce(bool_or(al.severity = 'warning' AND NOT al.suppressed), false) AS w
              FROM (SELECT DISTINCT unnest(ids) AS id) u JOIN agents g ON g.id = u.id
                   LEFT JOIN alerts al ON al.agent_id = g.id AND al.resolved_at IS NULL AND al.device_id IS NULL
             GROUP BY g.id) x
     WHERE a.id = x.id AND (a.open_alerts, a.alert_critical, a.alert_warning) IS DISTINCT FROM (x.n, x.c, x.w)
$$;
