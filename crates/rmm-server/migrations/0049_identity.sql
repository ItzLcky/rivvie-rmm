-- Identity management (docs/design/identity.md): per client, directories read through an agent
-- on a domain controller (Active Directory) or through Microsoft Graph (Entra ID), their users
-- and groups as last synced, and the actions technicians take on them.

CREATE TABLE identity_sources (
    id              uuid PRIMARY KEY,
    client_id       uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('ad', 'entra')),
    name            text NOT NULL,
    -- AD: the agent on a domain controller that runs the directory operations.
    agent_id        uuid REFERENCES agents(id) ON DELETE SET NULL,
    -- Entra: the app registration in the customer's tenant.
    tenant_id       text NOT NULL DEFAULT '',
    app_client_id   text NOT NULL DEFAULT '',
    -- The app's client secret, sealed with RMM_DATA_KEY when one is set (rotate::TABLES).
    secret          bytea,
    secret_sealed   boolean NOT NULL DEFAULT false,
    -- Also read Intune managed devices (docs/design/mdm.md); needs DeviceManagementManagedDevices.Read.All.
    sync_devices    boolean NOT NULL DEFAULT false,
    sync_minutes    integer NOT NULL DEFAULT 60 CHECK (sync_minutes BETWEEN 5 AND 1440),
    enabled         boolean NOT NULL DEFAULT true,
    last_sync_at    timestamptz,
    -- AD: when the last full (not delta) sync finished; group membership is only read in full.
    last_full_sync_at timestamptz,
    last_error      text,
    -- AD: the highest uSNChanged seen, for delta syncs (0: next sync is a full one).
    high_usn        bigint NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (client_id, name)
);
CREATE INDEX ON identity_sources (agent_id);

CREATE TABLE identity_users (
    id                   uuid PRIMARY KEY,
    source_id            uuid NOT NULL REFERENCES identity_sources(id) ON DELETE CASCADE,
    -- AD: the SID. Entra: the object id.
    external_id          text NOT NULL,
    username             text NOT NULL DEFAULT '',
    upn                  text NOT NULL DEFAULT '',
    display_name         text NOT NULL DEFAULT '',
    email                text NOT NULL DEFAULT '',
    enabled              boolean NOT NULL DEFAULT true,
    locked               boolean NOT NULL DEFAULT false,
    -- AD adminCount = 1, or an Entra directory role member: acting on it needs an admin.
    privileged           boolean NOT NULL DEFAULT false,
    -- Entra onPremisesSyncEnabled: changes are made in AD, not here.
    synced_from_ad       boolean NOT NULL DEFAULT false,
    last_logon_at        timestamptz,
    password_last_set    timestamptz,
    password_expires_at  timestamptz,
    mfa_registered       boolean,
    department           text NOT NULL DEFAULT '',
    title                text NOT NULL DEFAULT '',
    -- Matched to the client's contacts by email.
    contact_id           uuid REFERENCES contacts(id) ON DELETE SET NULL,
    -- Gone from the directory (kept so tickets and audit entries still name it).
    deleted_at           timestamptz,
    synced_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source_id, external_id)
);
CREATE INDEX ON identity_users (source_id, lower(display_name));
CREATE INDEX ON identity_users (contact_id);

CREATE TABLE identity_groups (
    id            uuid PRIMARY KEY,
    source_id     uuid NOT NULL REFERENCES identity_sources(id) ON DELETE CASCADE,
    external_id   text NOT NULL,
    name          text NOT NULL DEFAULT '',
    description   text NOT NULL DEFAULT '',
    -- Membership of it makes a user privileged (Domain Admins and friends; directory roles).
    privileged    boolean NOT NULL DEFAULT false,
    deleted_at    timestamptz,
    synced_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (source_id, external_id)
);

CREATE TABLE identity_group_members (
    group_id  uuid NOT NULL REFERENCES identity_groups(id) ON DELETE CASCADE,
    user_id   uuid NOT NULL REFERENCES identity_users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX ON identity_group_members (user_id);
