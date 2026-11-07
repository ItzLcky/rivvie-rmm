-- Tenancy: an MSP manages many clients; each client has one or more sites;
-- agents belong to exactly one site.

CREATE TABLE clients (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sites (
    id          uuid PRIMARY KEY,
    client_id   uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (client_id, name)
);

CREATE TABLE users (
    id             uuid PRIMARY KEY,
    email          text NOT NULL UNIQUE,
    name           text NOT NULL,
    password_hash  text NOT NULL,
    role           text NOT NULL CHECK (role IN ('admin', 'technician', 'readonly')),
    disabled       boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz
);

CREATE TABLE user_sessions (
    token_hash  bytea PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    user_agent  text
);
CREATE INDEX ON user_sessions (expires_at);

CREATE TABLE enrollment_tokens (
    id          uuid PRIMARY KEY,
    site_id     uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    token_hash  bytea NOT NULL UNIQUE,
    label       text NOT NULL DEFAULT '',
    max_uses    integer,               -- NULL = unlimited
    uses        integer NOT NULL DEFAULT 0,
    expires_at  timestamptz,           -- NULL = never
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agents (
    id              uuid PRIMARY KEY,
    site_id         uuid NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    secret_hash     bytea NOT NULL,
    machine_id      text,
    hostname        text NOT NULL,
    os_family       text NOT NULL,
    os_name         text NOT NULL DEFAULT '',
    os_version      text NOT NULL DEFAULT '',
    kernel_version  text NOT NULL DEFAULT '',
    arch            text NOT NULL DEFAULT '',
    agent_version   text NOT NULL DEFAULT '',
    enrolled_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz,
    online          boolean NOT NULL DEFAULT false,
    last_metrics    jsonb,
    inventory       jsonb,
    inventory_at    timestamptz
);
CREATE INDEX ON agents (site_id);
-- Re-enrolling the same machine into the same site reuses its agent record.
CREATE UNIQUE INDEX agents_site_machine ON agents (site_id, machine_id) WHERE machine_id IS NOT NULL;

-- Down-sampled time series for charts. Full Metrics payload lives in agents.last_metrics.
CREATE TABLE agent_metrics (
    agent_id      uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    ts            timestamptz NOT NULL,
    cpu_percent   real NOT NULL,
    mem_used      bigint NOT NULL,
    mem_total     bigint NOT NULL,
    disk_max_pct  real NOT NULL,
    net_rx_bytes  bigint NOT NULL,
    net_tx_bytes  bigint NOT NULL,
    PRIMARY KEY (agent_id, ts)
);
CREATE INDEX ON agent_metrics (ts);

CREATE TABLE scripts (
    id            uuid PRIMARY KEY,
    name          text NOT NULL UNIQUE,
    description   text NOT NULL DEFAULT '',
    interpreter   text NOT NULL,
    body          text NOT NULL,
    timeout_secs  integer NOT NULL DEFAULT 300,
    created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE jobs (
    id            uuid PRIMARY KEY,
    agent_id      uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    script_id     uuid REFERENCES scripts(id) ON DELETE SET NULL,
    interpreter   text NOT NULL,
    body          text NOT NULL,
    args          jsonb NOT NULL DEFAULT '[]',
    timeout_secs  integer NOT NULL,
    status        text NOT NULL DEFAULT 'queued'
                  CHECK (status IN ('queued', 'sent', 'succeeded', 'failed', 'timed_out', 'error', 'cancelled')),
    exit_code     integer,
    stdout        text NOT NULL DEFAULT '',
    stderr        text NOT NULL DEFAULT '',
    created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    sent_at       timestamptz,
    finished_at   timestamptz,
    duration_ms   bigint
);
CREATE INDEX ON jobs (agent_id, created_at DESC);
CREATE INDEX jobs_queued ON jobs (agent_id) WHERE status = 'queued';

CREATE TABLE audit_log (
    id           bigserial PRIMARY KEY,
    ts           timestamptz NOT NULL DEFAULT now(),
    user_id      uuid REFERENCES users(id) ON DELETE SET NULL,
    action       text NOT NULL,
    target_type  text,
    target_id    uuid,
    details      jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ON audit_log (ts DESC);
