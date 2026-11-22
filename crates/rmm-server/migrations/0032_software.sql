-- Software deployment (docs/design/software.md): a catalog of packages, what each agent has of
-- them, the installs, upgrades and removals run on agents, and the `software` policy module
-- ("these packages must be present / absent / kept current").

-- The catalog. client_id NULL: MSP-wide, usable everywhere; otherwise only that client's
-- policies and devices. A package says how to handle it on each platform: ids for winget,
-- Chocolatey, apt and dnf, and/or an uploaded installer (MSI or EXE, in object storage). A package
-- with none of them yet (installer still to upload) is kept in the catalog but can't be deployed.
CREATE TABLE software_packages (
    id              uuid PRIMARY KEY,
    client_id       uuid REFERENCES clients(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
    description     text NOT NULL DEFAULT '',
    publisher       text,
    winget_id       text,
    choco_id        text,
    apt_name        text,
    dnf_name        text,
    -- Pinned version; NULL installs and keeps the latest. For an uploaded installer this is the
    -- version the file installs (required, since nothing else says what "newer" means).
    version         text,
    installer_key   text,
    installer_name  text,
    installer_size  bigint,
    -- Lowercase hex.
    installer_sha256 text,
    installer_kind  text CHECK (installer_kind IN ('msi', 'exe')),
    silent_args     text NOT NULL DEFAULT '',
    uninstall_cmd   text,
    product_code    text,
    detect_name     text,
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CHECK ((installer_key IS NULL) = (installer_sha256 IS NULL))
);
CREATE UNIQUE INDEX software_packages_name ON software_packages (client_id, lower(name)) NULLS NOT DISTINCT;
CREATE INDEX software_packages_client ON software_packages (client_id);

-- What the last scan found, per agent and catalog package. `provider` NULL: no provider on
-- that machine could look (so "not installed" would be a guess and nothing is enforced).
CREATE TABLE software_state (
    agent_id          uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    package_id        uuid NOT NULL REFERENCES software_packages(id) ON DELETE CASCADE,
    installed_version text,
    available_version text,
    provider          text,
    checked_at        timestamptz NOT NULL DEFAULT now(),
    -- A version a person chose not to install (the updates view); a newer one shows again.
    ignored_version   text,
    -- Enforcement bookkeeping: failures in a row and when it last tried, for backing off.
    fail_count        integer NOT NULL DEFAULT 0,
    last_attempt_at   timestamptz,
    last_error        text,
    PRIMARY KEY (agent_id, package_id)
);
CREATE INDEX software_state_package ON software_state (package_id);
CREATE INDEX software_state_updates ON software_state (agent_id) WHERE available_version IS NOT NULL;

-- Per agent: which providers it has, and the state of the last scan.
CREATE TABLE software_agent_status (
    agent_id      uuid PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    providers     text[] NOT NULL DEFAULT '{}',
    scanned_at    timestamptz,
    requested_at  timestamptz,
    error         text
);

-- One run installs, upgrades or removes one package on one agent.
CREATE TABLE software_runs (
    id               uuid PRIMARY KEY,
    agent_id         uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    -- Kept (NULL) when the package is deleted from the catalog, with its name.
    package_id       uuid REFERENCES software_packages(id) ON DELETE SET NULL,
    package_name     text NOT NULL,
    op               text NOT NULL CHECK (op IN ('install', 'upgrade', 'uninstall')),
    trigger          text NOT NULL CHECK (trigger IN ('manual', 'policy')),
    policy_item_id   uuid REFERENCES policy_items(id) ON DELETE SET NULL,
    created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    bootstrap_choco  boolean NOT NULL DEFAULT false,
    status           text NOT NULL DEFAULT 'queued'
                     CHECK (status IN ('queued', 'sent', 'succeeded', 'failed', 'lost', 'expired', 'cancelled')),
    stage            text,
    progress         text,
    error            text,
    provider         text,
    from_version     text,
    to_version       text,
    reboot_required  boolean NOT NULL DEFAULT false,
    output           text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    sent_at          timestamptz,
    finished_at      timestamptz,
    duration_ms      bigint
);
CREATE INDEX software_runs_agent ON software_runs (agent_id, created_at DESC);
CREATE INDEX software_runs_package ON software_runs (package_id, created_at DESC);
CREATE INDEX software_runs_created ON software_runs (created_at DESC, id DESC);
CREATE INDEX software_runs_open ON software_runs (agent_id) WHERE status IN ('queued', 'sent');

-- The `software` policy module: one item per package requirement, in any set, with the usual
-- limit (client, site, excluded agents).
--   software:  {package_id, state: present|latest|absent, bootstrap_choco, window}
DO $$
DECLARE c record;
BEGIN
    FOR c IN SELECT conname FROM pg_constraint
              WHERE conrelid = 'policy_items'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%''alert''%' LOOP
        EXECUTE format('ALTER TABLE policy_items DROP CONSTRAINT %I', c.conname);
    END LOOP;
END $$;
ALTER TABLE policy_items ADD CONSTRAINT policy_items_module_check
    CHECK (module IN ('alert', 'schedule', 'patch', 'security', 'remote_access', 'agent', 'software'));
ALTER TABLE policy_items ADD CONSTRAINT policy_items_limit_check
    CHECK (module IN ('alert', 'schedule', 'software') OR (client_id IS NULL AND cardinality(excluded_agents) = 0));
