-- Phase 7, milestones 1-2: ticketing core, email-to-ticket and alert tickets.

-- People at a client. Separate from `users`: contacts are customers, users are MSP staff.
CREATE TABLE contacts (
    id              uuid PRIMARY KEY,
    client_id       uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    site_id         uuid REFERENCES sites(id) ON DELETE SET NULL,
    name            text NOT NULL,
    email           text NOT NULL DEFAULT '',
    phone           text NOT NULL DEFAULT '',
    job_title       text NOT NULL DEFAULT '',
    notes           text NOT NULL DEFAULT '',
    is_primary      boolean NOT NULL DEFAULT false,
    -- Used by the client portal (milestone 3).
    portal_enabled  boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON contacts (client_id, lower(name));
CREATE UNIQUE INDEX contacts_email ON contacts (client_id, lower(email)) WHERE email <> '';
CREATE INDEX contacts_email_lookup ON contacts (lower(email)) WHERE email <> '';

-- Mail from these domains is filed under the client when the sender isn't a known contact.
ALTER TABLE clients ADD COLUMN email_domains text[] NOT NULL DEFAULT '{}';

-- Queues. Each has an ordered set of statuses; the category drives filtering, reopening and
-- (later) SLA pausing and reporting.
CREATE TABLE boards (
    id           uuid PRIMARY KEY,
    name         text NOT NULL UNIQUE,
    description  text NOT NULL DEFAULT '',
    position     integer NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE board_statuses (
    id        uuid PRIMARY KEY,
    board_id  uuid NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
    name      text NOT NULL,
    category  text NOT NULL CHECK (category IN ('new', 'open', 'waiting_client', 'waiting_vendor', 'resolved', 'closed')),
    position  integer NOT NULL DEFAULT 0,
    UNIQUE (board_id, name)
);

CREATE TABLE ticket_types (
    id        uuid PRIMARY KEY,
    name      text NOT NULL UNIQUE,
    position  integer NOT NULL DEFAULT 0
);

-- Seed: a Service Desk board for people, an Alerts board for the RMM.
DO $$
DECLARE sd uuid := gen_random_uuid(); al uuid := gen_random_uuid();
BEGIN
    INSERT INTO boards (id, name, description, position) VALUES
        (sd, 'Service Desk', 'Requests and incidents from clients.', 0),
        (al, 'Alerts', 'Tickets opened by alert policies.', 1);
    INSERT INTO board_statuses (id, board_id, name, category, position)
    SELECT gen_random_uuid(), b, s.name, s.category, s.pos
      FROM unnest(ARRAY[sd, al]) b,
           (VALUES ('New', 'new', 0), ('In progress', 'open', 1), ('Waiting on client', 'waiting_client', 2),
                   ('Waiting on vendor', 'waiting_vendor', 3), ('Resolved', 'resolved', 4), ('Closed', 'closed', 5)) s(name, category, pos);
    INSERT INTO ticket_types (id, name, position) VALUES
        (gen_random_uuid(), 'Incident', 0), (gen_random_uuid(), 'Service request', 1),
        (gen_random_uuid(), 'Problem', 2), (gen_random_uuid(), 'Change', 3), (gen_random_uuid(), 'Alert', 4);
END $$;

-- Inbound support mailboxes. kind:
--   imap:    polled with a username and password (or app password)
--   webhook: a provider (Postmark, Mailgun, SES via a forwarder) posts raw MIME to
--            /api/inbound/email/{token}; only the token's hash is stored.
-- The IMAP password is stored as-is, like the SMTP password: use an account limited to this mailbox.
CREATE TABLE mailboxes (
    id                  uuid PRIMARY KEY,
    name                text NOT NULL UNIQUE,
    address             text NOT NULL,
    kind                text NOT NULL CHECK (kind IN ('imap', 'webhook')),
    imap_host           text NOT NULL DEFAULT '',
    imap_port           integer NOT NULL DEFAULT 993 CHECK (imap_port BETWEEN 1 AND 65535),
    imap_security       text NOT NULL DEFAULT 'tls' CHECK (imap_security IN ('tls', 'none')),
    imap_username       text NOT NULL DEFAULT '',
    imap_password       text NOT NULL DEFAULT '',
    imap_folder         text NOT NULL DEFAULT 'INBOX',
    webhook_token_hash  bytea UNIQUE,
    board_id            uuid NOT NULL REFERENCES boards(id),
    -- Acknowledge new tickets by email (rate-limited per sender).
    auto_reply          boolean NOT NULL DEFAULT false,
    enabled             boolean NOT NULL DEFAULT true,
    last_polled_at      timestamptz,
    last_error          text,
    created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX mailboxes_address ON mailboxes (lower(address));

-- Human ticket numbers (T-10001). Gaps are fine: these aren't invoice numbers.
CREATE SEQUENCE ticket_number_seq START 10001;

CREATE TABLE tickets (
    id                 uuid PRIMARY KEY,
    number             bigint NOT NULL UNIQUE DEFAULT nextval('ticket_number_seq'),
    -- NULL: triage (mail from an unknown sender). Only users who see every client see these.
    client_id          uuid REFERENCES clients(id) ON DELETE CASCADE,
    site_id            uuid REFERENCES sites(id) ON DELETE SET NULL,
    contact_id         uuid REFERENCES contacts(id) ON DELETE SET NULL,
    board_id           uuid NOT NULL REFERENCES boards(id),
    status_id          uuid NOT NULL REFERENCES board_statuses(id),
    type_id            uuid REFERENCES ticket_types(id) ON DELETE SET NULL,
    -- 1 (critical) to 4 (low). Set directly, or from impact x urgency.
    priority           smallint NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 4),
    impact             smallint CHECK (impact BETWEEN 1 AND 3),
    urgency            smallint CHECK (urgency BETWEEN 1 AND 3),
    subject            text NOT NULL,
    source             text NOT NULL CHECK (source IN ('dashboard', 'email', 'alert', 'portal', 'api')),
    assignee_id        uuid REFERENCES users(id) ON DELETE SET NULL,
    -- Who to reply to when there's no contact (an unknown sender).
    requester_name     text NOT NULL DEFAULT '',
    requester_email    text NOT NULL DEFAULT '',
    mailbox_id         uuid REFERENCES mailboxes(id) ON DELETE SET NULL,
    created_by         uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    -- First public reply by a technician.
    first_response_at  timestamptz,
    resolved_at        timestamptz,
    closed_at          timestamptz,
    -- Last time a person (not automation) changed or commented on it.
    touched_at         timestamptz,
    -- Alert tickets: the (policy, agent, key) that opened it, and how often it reopened.
    alert_policy_id    uuid REFERENCES alert_policies(id) ON DELETE SET NULL,
    alert_agent_id     uuid REFERENCES agents(id) ON DELETE SET NULL,
    alert_key          text,
    alert_reopens      integer NOT NULL DEFAULT 0,
    merged_into        uuid REFERENCES tickets(id) ON DELETE SET NULL,
    -- Subject, every event's text and the contact name; maintained by triggers below.
    search             tsvector NOT NULL DEFAULT ''::tsvector
);
CREATE INDEX tickets_client ON tickets (client_id, updated_at DESC);
CREATE INDEX tickets_updated ON tickets (updated_at DESC, id DESC);
CREATE INDEX tickets_assignee ON tickets (assignee_id) WHERE assignee_id IS NOT NULL;
CREATE INDEX tickets_contact ON tickets (contact_id) WHERE contact_id IS NOT NULL;
CREATE INDEX tickets_status ON tickets (status_id);
CREATE INDEX tickets_alert ON tickets (alert_policy_id, alert_agent_id, alert_key) WHERE alert_policy_id IS NOT NULL;
CREATE INDEX tickets_search ON tickets USING gin (search);

-- Append-only timeline. kind:
--   created, reply (public, to the client), message (from the client: email or portal),
--   note (internal), change (data: {field, from, to}), alert (opened/cleared), job (a script
--   run's result), session (terminal / remote desktop), merge, agent (linked/unlinked)
CREATE TABLE ticket_events (
    id                 bigserial PRIMARY KEY,
    ticket_id          uuid NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    kind               text NOT NULL CHECK (kind IN ('created', 'reply', 'message', 'note', 'change', 'alert', 'job', 'session', 'merge', 'agent')),
    -- Visible to the client (replies and their own messages).
    public             boolean NOT NULL DEFAULT false,
    author_id          uuid REFERENCES users(id) ON DELETE SET NULL,
    author_contact_id  uuid REFERENCES contacts(id) ON DELETE SET NULL,
    -- Display name when the author isn't a user (email senders, automation).
    author_name        text NOT NULL DEFAULT '',
    body               text NOT NULL DEFAULT '',
    data               jsonb NOT NULL DEFAULT '{}',
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON ticket_events (ticket_id, id);

-- Files in object storage (RMM_STORAGE_DIR or S3).
CREATE TABLE ticket_attachments (
    id            uuid PRIMARY KEY,
    ticket_id     uuid NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    event_id      bigint REFERENCES ticket_events(id) ON DELETE SET NULL,
    name          text NOT NULL,
    content_type  text NOT NULL,
    size          bigint NOT NULL,
    sha256        bytea NOT NULL,
    storage_key   text NOT NULL,
    uploaded_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON ticket_attachments (ticket_id);

-- Agents a ticket is about: the ticket page shows their live state.
CREATE TABLE ticket_agents (
    ticket_id  uuid NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    agent_id   uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    added_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    added_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ticket_id, agent_id)
);
CREATE INDEX ON ticket_agents (agent_id);

-- A script run from a ticket: its result is added to the timeline.
ALTER TABLE jobs ADD COLUMN ticket_id uuid REFERENCES tickets(id) ON DELETE SET NULL;

-- Mail in both directions. Inbound rows record what arrived (and why it was ignored); outbound
-- rows are an outbox drained by the notification worker. message_id is without angle brackets.
CREATE TABLE email_messages (
    id               uuid PRIMARY KEY,
    direction        text NOT NULL CHECK (direction IN ('in', 'out')),
    mailbox_id       uuid REFERENCES mailboxes(id) ON DELETE SET NULL,
    ticket_id        uuid REFERENCES tickets(id) ON DELETE SET NULL,
    event_id         bigint REFERENCES ticket_events(id) ON DELETE SET NULL,
    message_id       text NOT NULL,
    in_reply_to      text,
    "references"     text[] NOT NULL DEFAULT '{}',
    from_addr        text NOT NULL DEFAULT '',
    to_addrs         text[] NOT NULL DEFAULT '{}',
    cc_addrs         text[] NOT NULL DEFAULT '{}',
    reply_to         text,
    subject          text NOT NULL DEFAULT '',
    -- Outbound: what to send.
    body             text NOT NULL DEFAULT '',
    -- Inbound: the raw MIME in object storage.
    raw_key          text,
    -- in: received / ignored;  out: pending / sent / failed
    status           text NOT NULL CHECK (status IN ('received', 'ignored', 'pending', 'sent', 'failed')),
    ignored_reason   text,
    -- auto_reply, reply, assigned: what an outbound message is (rate limits count auto_reply).
    purpose          text,
    attempts         integer NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_error       text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    sent_at          timestamptz
);
CREATE UNIQUE INDEX email_in_message_id ON email_messages (message_id) WHERE direction = 'in';
CREATE INDEX email_message_id ON email_messages (message_id);
CREATE INDEX email_outbox_due ON email_messages (next_attempt_at) WHERE status = 'pending';
CREATE INDEX ON email_messages (ticket_id, created_at);
CREATE INDEX ON email_messages (created_at);
CREATE INDEX email_auto_reply ON email_messages (lower(to_addrs[1]), created_at) WHERE purpose = 'auto_reply';

-- Alert policies can open tickets.
ALTER TABLE alert_policies ADD COLUMN ticket_board_id uuid REFERENCES boards(id) ON DELETE SET NULL;
ALTER TABLE alert_policies ADD COLUMN ticket_priority smallint NOT NULL DEFAULT 3 CHECK (ticket_priority BETWEEN 1 AND 4);
-- Resolve the ticket when the alert clears, if nobody has touched it.
ALTER TABLE alert_policies ADD COLUMN ticket_auto_resolve boolean NOT NULL DEFAULT false;

-- Full-text search: subject + contact name, plus each event's text as it's added.
CREATE FUNCTION tickets_search_base(t tickets) RETURNS tsvector LANGUAGE sql STABLE AS $$
    SELECT setweight(to_tsvector('simple', coalesce(t.subject, '')), 'A')
        || setweight(to_tsvector('simple', coalesce((SELECT name || ' ' || email FROM contacts WHERE id = t.contact_id), '')), 'B')
        || setweight(to_tsvector('simple', coalesce(t.requester_name, '') || ' ' || coalesce(t.requester_email, '')), 'B')
$$;

CREATE FUNCTION tickets_search_refresh() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.search := tickets_search_base(NEW)
        || coalesce((SELECT setweight(to_tsvector('simple', string_agg(left(body, 20000), ' ')), 'C')
                       FROM ticket_events WHERE ticket_id = NEW.id), ''::tsvector);
    RETURN NEW;
END $$;
CREATE TRIGGER tickets_search_refresh BEFORE INSERT OR UPDATE OF subject, contact_id, requester_name, requester_email ON tickets
    FOR EACH ROW EXECUTE FUNCTION tickets_search_refresh();

CREATE FUNCTION ticket_events_search() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.body <> '' THEN
        UPDATE tickets SET search = search || setweight(to_tsvector('simple', left(NEW.body, 20000)), 'C') WHERE id = NEW.ticket_id;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER ticket_events_search AFTER INSERT ON ticket_events FOR EACH ROW EXECUTE FUNCTION ticket_events_search();
