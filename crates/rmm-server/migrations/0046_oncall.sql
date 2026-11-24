-- On-call and paging (docs/design/oncall.md): schedules with rotation layers and overrides,
-- escalation policies, pages and their deliveries, per-user contact methods, and three
-- external channel kinds (SMS, PagerDuty, Opsgenie) plus `oncall`, which pages instead of
-- broadcasting.

-- Channel kinds. Secrets (the PagerDuty routing key, the Opsgenie API key) live in the existing
-- sealed `secret` column. NOTE for merges: other tracks may also re-declare this check; the
-- final list must be the union.
ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_kind_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_kind_check
    CHECK (kind IN ('email', 'webhook', 'slack', 'teams', 'sms', 'pagerduty', 'opsgenie', 'oncall'));

-- The SMS provider (Twilio's Messages API, or anything compatible with it). The auth token is
-- sealed with RMM_DATA_KEY when the server has one.
ALTER TABLE company_settings
    ADD COLUMN sms_account_sid  text NOT NULL DEFAULT '',
    ADD COLUMN sms_from         text NOT NULL DEFAULT '',
    ADD COLUMN sms_base_url     text NOT NULL DEFAULT 'https://api.twilio.com',
    ADD COLUMN sms_token_enc    bytea,
    ADD COLUMN sms_token_sealed boolean NOT NULL DEFAULT false;

-- A mobile number (E.164) that can be texted once it is verified with a code.
ALTER TABLE users
    ADD COLUMN phone                  text CHECK (phone ~ '^\+[1-9][0-9]{6,14}$'),
    ADD COLUMN phone_verified_at      timestamptz,
    ADD COLUMN phone_code_hash        bytea,
    ADD COLUMN phone_code_expires_at  timestamptz;

CREATE TABLE oncall_schedules (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    -- Rotations hand over and restrictions apply in this zone.
    timezone    text NOT NULL DEFAULT 'UTC',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- A rotation through `user_ids`, one shift of `shift_hours` each, starting at `start_at`.
-- Shifts that are whole days hand over at the start's local time even across DST changes.
-- `restrict` is a list of {days: [0-6, Monday = 0], start: minute, end: minute} windows in the
-- schedule's zone (end <= start runs past midnight); empty = always. Where layers overlap, the
-- highest `position` that has someone on wins.
CREATE TABLE oncall_layers (
    id           uuid PRIMARY KEY,
    schedule_id  uuid NOT NULL REFERENCES oncall_schedules(id) ON DELETE CASCADE,
    position     integer NOT NULL,
    name         text NOT NULL DEFAULT '',
    user_ids     uuid[] NOT NULL DEFAULT '{}',
    start_at     timestamptz NOT NULL,
    shift_hours  integer NOT NULL CHECK (shift_hours BETWEEN 1 AND 672),
    restrict     jsonb NOT NULL DEFAULT '[]',
    UNIQUE (schedule_id, position)
);

-- Someone else on for a while: wins over every layer.
CREATE TABLE oncall_overrides (
    id           uuid PRIMARY KEY,
    schedule_id  uuid NOT NULL REFERENCES oncall_schedules(id) ON DELETE CASCADE,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    starts_at    timestamptz NOT NULL,
    ends_at      timestamptz NOT NULL CHECK (ends_at > starts_at),
    created_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON oncall_overrides (schedule_id, ends_at);

-- Steps run in order; each waits `delay_minutes` for an acknowledgement before the next.
-- After the last step the policy starts again from the first, `repeat` more times.
CREATE TABLE escalation_policies (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    repeat      integer NOT NULL DEFAULT 0 CHECK (repeat BETWEEN 0 AND 9),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- `targets`: a list of {"schedule": id} (whoever is on call), {"user": id} or {"channel": id}.
CREATE TABLE escalation_steps (
    policy_id      uuid NOT NULL REFERENCES escalation_policies(id) ON DELETE CASCADE,
    position       integer NOT NULL,
    delay_minutes  integer NOT NULL CHECK (delay_minutes BETWEEN 1 AND 1440),
    targets        jsonb NOT NULL DEFAULT '[]',
    PRIMARY KEY (policy_id, position)
);

-- Page a new P1 ticket through this policy (optional).
ALTER TABLE company_settings ADD COLUMN p1_escalation_policy_id uuid REFERENCES escalation_policies(id) ON DELETE SET NULL;

-- One escalation in progress, for an alert or a ticket.
--   held:          an `outside_hours` channel inside business hours; starts at next_escalation_at
--   triggered:     escalating; the next step is due at next_escalation_at (NULL: steps exhausted)
--   acknowledged, resolved: done
CREATE TABLE pages (
    id                  uuid PRIMARY KEY,
    alert_id            uuid REFERENCES alerts(id) ON DELETE CASCADE,
    ticket_id           uuid REFERENCES tickets(id) ON DELETE CASCADE,
    channel_id          uuid REFERENCES notification_channels(id) ON DELETE SET NULL,
    policy_id           uuid REFERENCES escalation_policies(id) ON DELETE SET NULL,
    title               text NOT NULL,
    severity            text NOT NULL DEFAULT 'critical',
    step                integer NOT NULL DEFAULT 0,
    round               integer NOT NULL DEFAULT 0,
    status              text NOT NULL CHECK (status IN ('held', 'triggered', 'acknowledged', 'resolved')),
    next_escalation_at  timestamptz,
    -- When the current step was notified (NULL: step one hasn't been yet).
    last_step_at        timestamptz,
    acked_by            uuid REFERENCES users(id) ON DELETE SET NULL,
    acked_at            timestamptz,
    resolved_at         timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    CHECK (alert_id IS NOT NULL OR ticket_id IS NOT NULL)
);
CREATE INDEX ON pages (alert_id);
CREATE INDEX ON pages (ticket_id);
CREATE INDEX ON pages (next_escalation_at) WHERE status IN ('held', 'triggered');
-- One open page per alert (or ticket) and policy.
CREATE UNIQUE INDEX pages_open_alert ON pages (alert_id, policy_id) WHERE alert_id IS NOT NULL AND status IN ('held', 'triggered');
CREATE UNIQUE INDEX pages_open_ticket ON pages (ticket_id, policy_id) WHERE ticket_id IS NOT NULL AND status IN ('held', 'triggered');

-- One message to one person (or a step's channel), retried with backoff.
CREATE TABLE page_deliveries (
    id               uuid PRIMARY KEY,
    page_id          uuid NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    user_id          uuid REFERENCES users(id) ON DELETE CASCADE,
    channel_id       uuid REFERENCES notification_channels(id) ON DELETE SET NULL,
    method           text NOT NULL CHECK (method IN ('sms', 'email', 'push', 'channel')),
    step             integer NOT NULL DEFAULT 0,
    round            integer NOT NULL DEFAULT 0,
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'cancelled')),
    attempts         integer NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    error            text,
    provider_ref     text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    sent_at          timestamptz
);
CREATE INDEX ON page_deliveries (page_id);
CREATE INDEX ON page_deliveries (next_attempt_at) WHERE status = 'pending';

-- The `/a/<token>` short link in a text message: opens the page's alert or ticket once, for 24
-- hours (acting on it still needs a session).
CREATE TABLE page_links (
    token_hash  bytea PRIMARY KEY,
    page_id     uuid NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    user_id     uuid REFERENCES users(id) ON DELETE CASCADE,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);

-- How a person wants to be reached when paged: each method after a delay. No rows: email and
-- push at once, and a text message too when the phone is verified.
CREATE TABLE user_contact_rules (
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method         text NOT NULL CHECK (method IN ('sms', 'email', 'push')),
    delay_minutes  integer NOT NULL DEFAULT 0 CHECK (delay_minutes BETWEEN 0 AND 120),
    PRIMARY KEY (user_id, method, delay_minutes)
);
