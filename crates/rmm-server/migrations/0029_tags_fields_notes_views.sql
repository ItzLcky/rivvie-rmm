-- Tags, custom fields, agent notes and saved views (docs/design/fields.md).

-- Tags are MSP-wide labels on agents. Names are unique ignoring case.
CREATE TABLE tags (
    id          uuid PRIMARY KEY,
    name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 40),
    -- One of the palette names the dashboard knows (slate, red, orange, amber, green, teal, blue, violet, pink).
    color       text NOT NULL DEFAULT 'slate',
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX tags_name_key ON tags (lower(name));

CREATE TABLE agent_tags (
    agent_id    uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    tag_id      uuid NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, tag_id)
);
-- "Agents with this tag" (the list filter) and counts per tag.
CREATE INDEX agent_tags_tag ON agent_tags (tag_id, agent_id);

-- Admin-defined fields on agents, clients and sites. `name` is the stable key scripts and the API
-- use (lowercase letters, digits and underscores); `label` is what people read. A field with a
-- `client_id` exists only for that client's agents and sites, and only people who can see that
-- client see it at all.
CREATE TABLE custom_fields (
    id               uuid PRIMARY KEY,
    entity           text NOT NULL CHECK (entity IN ('agent', 'client', 'site')),
    name             text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]{0,39}$'),
    label            text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 80),
    description      text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
    kind             text NOT NULL CHECK (kind IN ('text', 'number', 'bool', 'date', 'select')),
    -- The choices of a select field.
    options          text[] NOT NULL DEFAULT '{}',
    client_id        uuid REFERENCES clients(id) ON DELETE CASCADE,
    -- A script may set it by printing `RMM-FIELD name=value` (agent fields only).
    script_writable  boolean NOT NULL DEFAULT false,
    position         integer NOT NULL DEFAULT 0,
    created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (entity <> 'client' OR client_id IS NULL),
    CHECK (NOT script_writable OR entity = 'agent'),
    CHECK ((kind = 'select') = (cardinality(options) > 0))
);
CREATE UNIQUE INDEX custom_fields_name_key ON custom_fields (entity, name);

-- One value per field and entity, JSON typed by the field's kind: text and select a string,
-- number a number, bool a boolean, date 'YYYY-MM-DD'. Exactly one of the three ids is set, so
-- deleting the agent, client or site takes its values with it.
CREATE TABLE custom_field_values (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    field_id    uuid NOT NULL REFERENCES custom_fields(id) ON DELETE CASCADE,
    agent_id    uuid REFERENCES agents(id) ON DELETE CASCADE,
    client_id   uuid REFERENCES clients(id) ON DELETE CASCADE,
    site_id     uuid REFERENCES sites(id) ON DELETE CASCADE,
    value       jsonb NOT NULL,
    -- user, api (a key) or script.
    source      text NOT NULL DEFAULT 'user' CHECK (source IN ('user', 'api', 'script')),
    updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    -- The job whose output set it, while that job still exists.
    job_id      uuid REFERENCES jobs(id) ON DELETE SET NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(agent_id, client_id, site_id) = 1)
);
CREATE UNIQUE INDEX custom_field_values_agent ON custom_field_values (agent_id, field_id) WHERE agent_id IS NOT NULL;
CREATE UNIQUE INDEX custom_field_values_client ON custom_field_values (client_id, field_id) WHERE client_id IS NOT NULL;
CREATE UNIQUE INDEX custom_field_values_site ON custom_field_values (site_id, field_id) WHERE site_id IS NOT NULL;
-- The agents list filter: agents whose field has a value.
CREATE INDEX custom_field_values_by_field ON custom_field_values (field_id, agent_id) WHERE agent_id IS NOT NULL;

-- Notes on an agent: timestamped, authored, editable by the author (and admins). At most one is
-- pinned; it's shown in the agent's header.
CREATE TABLE agent_notes (
    id           uuid PRIMARY KEY,
    agent_id     uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    body         text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 10000),
    author_id    uuid REFERENCES users(id) ON DELETE SET NULL,
    -- The author's name when the note was written, for after their account is gone.
    author_name  text NOT NULL,
    pinned       boolean NOT NULL DEFAULT false,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_notes_agent ON agent_notes (agent_id, created_at DESC);
CREATE UNIQUE INDEX agent_notes_one_pinned ON agent_notes (agent_id) WHERE pinned;

-- A named list state: the query string of a list page (filters, sort), and the columns it hides.
-- `shared` views are listed for everyone; a view bound to a client (its query has `client=`) is
-- listed only to people who can see that client.
CREATE TABLE saved_views (
    id          uuid PRIMARY KEY,
    page        text NOT NULL CHECK (page IN ('agents')),
    name        text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
    owner_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    shared      boolean NOT NULL DEFAULT false,
    query       text NOT NULL CHECK (char_length(query) <= 2000),
    -- Column ids to hide (the table's own preference format); NULL leaves the columns alone.
    hidden_columns text[],
    client_id   uuid REFERENCES clients(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX saved_views_name_key ON saved_views (page, owner_id, lower(name));
CREATE INDEX saved_views_shared ON saved_views (page) WHERE shared;
