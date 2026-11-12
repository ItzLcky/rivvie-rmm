-- Roadmap block 4 (PSA milestones 3-4): the client portal, the SLA engine, and what was left
-- over from milestones 1-2 (Microsoft Graph mailboxes, teams, split, canned responses and
-- macros, satisfaction surveys, per-board new-ticket notifications).

-- ---------------------------------------------------------------------------
-- Client portal
-- ---------------------------------------------------------------------------

-- Contacts sign in with a one-time emailed link, or a password they set (plus an optional
-- TOTP). Kept apart from `users` and `user_sessions`: a portal session can never reach the
-- technician API, and a technician cookie never reaches the portal.
CREATE TABLE contact_credentials (
    contact_id      uuid PRIMARY KEY REFERENCES contacts(id) ON DELETE CASCADE,
    password_hash   text,
    totp_secret     bytea,
    totp_sealed     boolean NOT NULL DEFAULT false,
    totp_last_step  bigint,
    -- Set up but not confirmed yet.
    totp_pending    bytea,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE contact_sessions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash    bytea NOT NULL UNIQUE,
    contact_id    uuid NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    user_agent    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);
CREATE INDEX ON contact_sessions (contact_id);

-- Sign-in links (and invitations). Only the token's hash is stored; each works once.
CREATE TABLE contact_login_links (
    token_hash  bytea PRIMARY KEY,
    contact_id  uuid NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    purpose     text NOT NULL DEFAULT 'login' CHECK (purpose IN ('login', 'invite')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);
CREATE INDEX ON contact_login_links (contact_id);

ALTER TABLE contacts ADD COLUMN portal_last_login_at timestamptz;
-- Contacts see their own tickets; primary contacts and these see every ticket of the client.
ALTER TABLE contacts ADD COLUMN portal_all_tickets boolean NOT NULL DEFAULT false;
-- The portal's device status list, off by default.
ALTER TABLE clients ADD COLUMN portal_devices boolean NOT NULL DEFAULT false;

-- Tickets opened in the portal go to this board (else the first board).
ALTER TABLE company_settings ADD COLUMN portal_board_id uuid REFERENCES boards(id) ON DELETE SET NULL;
ALTER TABLE company_settings ADD COLUMN portal_welcome text NOT NULL DEFAULT '';

-- Files contacts upload from the portal.
ALTER TABLE ticket_attachments ADD COLUMN uploaded_by_contact uuid REFERENCES contacts(id) ON DELETE SET NULL;

-- Knowledge base. Public articles show in the portal (to every client, or to one).
CREATE TABLE kb_articles (
    id          uuid PRIMARY KEY,
    title       text NOT NULL,
    body        text NOT NULL DEFAULT '',
    category    text NOT NULL DEFAULT '',
    public      boolean NOT NULL DEFAULT false,
    client_id   uuid REFERENCES clients(id) ON DELETE CASCADE,
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    search      tsvector GENERATED ALWAYS AS (
                    setweight(to_tsvector('simple', title), 'A') || setweight(to_tsvector('simple', category), 'B')
                    || setweight(to_tsvector('simple', left(body, 50000)), 'C')) STORED
);
CREATE INDEX ON kb_articles USING gin (search);
CREATE INDEX ON kb_articles (lower(category), lower(title));

-- ---------------------------------------------------------------------------
-- SLAs
-- ---------------------------------------------------------------------------

-- Business hours. `hours` has one entry per weekday, Monday first: a list of
-- [start_minute, end_minute] pairs in the calendar's time zone, e.g. [[480, 1020]] = 08:00-17:00.
CREATE TABLE business_calendars (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    timezone    text NOT NULL DEFAULT 'UTC',
    hours       jsonb NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE holidays (
    calendar_id  uuid NOT NULL REFERENCES business_calendars(id) ON DELETE CASCADE,
    day          date NOT NULL,
    name         text NOT NULL DEFAULT '',
    PRIMARY KEY (calendar_id, day)
);

-- Targets are per priority. No calendar: the clock runs around the clock.
CREATE TABLE sla_policies (
    id               uuid PRIMARY KEY,
    name             text NOT NULL UNIQUE,
    calendar_id      uuid REFERENCES business_calendars(id) ON DELETE SET NULL,
    -- Used for clients without a policy of their own.
    is_default       boolean NOT NULL DEFAULT false,
    -- Warnings (75%) and breaches go to these channels, and to the assignee by email.
    channel_ids      uuid[] NOT NULL DEFAULT '{}',
    notify_assignee  boolean NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX sla_policies_default ON sla_policies (is_default) WHERE is_default;

-- Minutes of business time. NULL: no target of that kind.
--   respond: to the first public reply by a technician
--   update:  between public replies once the first one is in
--   resolve: to resolved
CREATE TABLE sla_targets (
    policy_id     uuid NOT NULL REFERENCES sla_policies(id) ON DELETE CASCADE,
    priority      smallint NOT NULL CHECK (priority BETWEEN 1 AND 4),
    respond_mins  integer CHECK (respond_mins > 0),
    update_mins   integer CHECK (update_mins > 0),
    resolve_mins  integer CHECK (resolve_mins > 0),
    PRIMARY KEY (policy_id, priority)
);

ALTER TABLE clients ADD COLUMN sla_policy_id uuid REFERENCES sla_policies(id) ON DELETE SET NULL;

-- Deadlines are stored so lists can sort and filter on them. The clock pauses while the ticket
-- waits on the client (or sits resolved); `sla_paused_secs` is the business time spent paused,
-- which pushes every deadline back.
ALTER TABLE tickets
    ADD COLUMN sla_policy_id           uuid REFERENCES sla_policies(id) ON DELETE SET NULL,
    ADD COLUMN respond_by              timestamptz,
    ADD COLUMN update_by               timestamptz,
    ADD COLUMN resolve_by              timestamptz,
    ADD COLUMN respond_warn_at         timestamptz,
    ADD COLUMN update_warn_at          timestamptz,
    ADD COLUMN resolve_warn_at         timestamptz,
    ADD COLUMN sla_paused_at           timestamptz,
    ADD COLUMN sla_paused_secs         bigint NOT NULL DEFAULT 0,
    -- The update clock: the last public reply, and the pause total at that moment.
    ADD COLUMN sla_update_from         timestamptz,
    ADD COLUMN sla_update_paused_base  bigint NOT NULL DEFAULT 0,
    -- Targets (respond / update / resolve) warned about and breached.
    ADD COLUMN sla_warned              text[] NOT NULL DEFAULT '{}',
    ADD COLUMN sla_breached            text[] NOT NULL DEFAULT '{}',
    ADD COLUMN sla_breached_at         timestamptz;
CREATE INDEX tickets_sla ON tickets (sla_policy_id) WHERE sla_policy_id IS NOT NULL AND sla_paused_at IS NULL;

-- ---------------------------------------------------------------------------
-- Teams, splitting, canned responses, surveys, board notifications
-- ---------------------------------------------------------------------------

CREATE TABLE teams (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE team_members (
    team_id  uuid NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (team_id, user_id)
);
CREATE INDEX ON team_members (user_id);
ALTER TABLE tickets ADD COLUMN team_id uuid REFERENCES teams(id) ON DELETE SET NULL;
CREATE INDEX tickets_team ON tickets (team_id) WHERE team_id IS NOT NULL;

-- New tickets on the board go to this team, and are announced on these channels.
ALTER TABLE boards ADD COLUMN default_team_id uuid REFERENCES teams(id) ON DELETE SET NULL;
ALTER TABLE boards ADD COLUMN notify_channel_ids uuid[] NOT NULL DEFAULT '{}';

-- Canned responses: text with {{variables}}, and optionally a macro's actions. owner_id NULL is
-- shared (admins manage those); otherwise only the owner sees it.
CREATE TABLE canned_responses (
    id               uuid PRIMARY KEY,
    name             text NOT NULL,
    body             text NOT NULL DEFAULT '',
    kind             text NOT NULL DEFAULT 'reply' CHECK (kind IN ('reply', 'note')),
    status_category  text CHECK (status_category IN ('new', 'open', 'waiting_client', 'waiting_vendor', 'resolved', 'closed')),
    priority         smallint CHECK (priority BETWEEN 1 AND 4),
    assign           text CHECK (assign IN ('me', 'none')),
    owner_id         uuid REFERENCES users(id) ON DELETE CASCADE,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON canned_responses (owner_id, lower(name));

-- One satisfaction survey per ticket, sent when it's resolved.
ALTER TABLE company_settings ADD COLUMN csat_enabled boolean NOT NULL DEFAULT false;
CREATE TABLE csat_surveys (
    ticket_id    uuid PRIMARY KEY REFERENCES tickets(id) ON DELETE CASCADE,
    token_hash   bytea NOT NULL UNIQUE,
    contact_id   uuid REFERENCES contacts(id) ON DELETE SET NULL,
    email        text NOT NULL,
    sent_at      timestamptz NOT NULL DEFAULT now(),
    rating       text CHECK (rating IN ('good', 'bad')),
    comment      text NOT NULL DEFAULT '',
    answered_at  timestamptz
);
CREATE INDEX ON csat_surveys (answered_at) WHERE answered_at IS NOT NULL;

ALTER TABLE ticket_events DROP CONSTRAINT ticket_events_kind_check;
ALTER TABLE ticket_events ADD CONSTRAINT ticket_events_kind_check CHECK (kind IN (
    'created', 'reply', 'message', 'note', 'change', 'alert', 'job', 'session', 'merge', 'agent', 'sla', 'split', 'csat'));

-- Notifications about tickets (SLA warnings and breaches, new tickets on a board).
ALTER TABLE notifications ADD COLUMN ticket_id uuid REFERENCES tickets(id) ON DELETE CASCADE;
ALTER TABLE notifications ADD COLUMN data jsonb NOT NULL DEFAULT '{}';
ALTER TABLE notifications DROP CONSTRAINT notifications_event_check;
ALTER TABLE notifications ADD CONSTRAINT notifications_event_check
    CHECK (event IN ('opened', 'resolved', 'reminder', 'test', 'sla_warning', 'sla_breach', 'ticket_created'));
CREATE INDEX ON notifications (ticket_id) WHERE ticket_id IS NOT NULL;

-- Ticket mail remembers the mailbox it goes out through (Graph mailboxes send themselves).
-- `mailbox_id` already exists on email_messages for inbound rows.

-- ---------------------------------------------------------------------------
-- Microsoft Graph mailboxes (M365 turned basic-auth IMAP off)
-- ---------------------------------------------------------------------------

-- An app registration with Mail.ReadWrite and Mail.Send (application permissions, ideally
-- limited to the mailbox with an application access policy). The secret is sealed with
-- RMM_DATA_KEY when it's set.
ALTER TABLE mailboxes DROP CONSTRAINT mailboxes_kind_check;
ALTER TABLE mailboxes ADD CONSTRAINT mailboxes_kind_check CHECK (kind IN ('imap', 'webhook', 'graph'));
ALTER TABLE mailboxes
    ADD COLUMN graph_tenant         text NOT NULL DEFAULT '',
    ADD COLUMN graph_client_id      text NOT NULL DEFAULT '',
    ADD COLUMN graph_secret         bytea,
    ADD COLUMN graph_secret_sealed  boolean NOT NULL DEFAULT false,
    -- Send replies through Graph too, instead of the SMTP server.
    ADD COLUMN graph_send           boolean NOT NULL DEFAULT true;
