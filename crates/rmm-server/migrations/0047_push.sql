-- Web Push for the installable dashboard (docs/design/pwa.md).

-- The server's VAPID key pair (ECDSA P-256), made on first use. `public` is the uncompressed
-- point; `private` is PKCS#8, sealed with RMM_DATA_KEY when the server has one.
CREATE TABLE push_keys (
    id              boolean PRIMARY KEY DEFAULT true CHECK (id),
    public          bytea NOT NULL,
    private         bytea NOT NULL,
    private_sealed  boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- One browser on one device. `p256dh` and `auth` are the subscription's keys (RFC 8291).
CREATE TABLE push_subscriptions (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint    text NOT NULL UNIQUE,
    p256dh      bytea NOT NULL,
    auth        bytea NOT NULL,
    user_agent  text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_ok_at  timestamptz,
    failures    integer NOT NULL DEFAULT 0
);
CREATE INDEX ON push_subscriptions (user_id);

-- What a person wants on their devices (push) and by email, per event. No row: the defaults in
-- push.rs.
CREATE TABLE user_notification_prefs (
    user_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event    text NOT NULL CHECK (event IN ('alert_critical', 'alert_warning', 'page', 'ticket_assigned', 'ticket_reply', 'sla_warning')),
    push     boolean NOT NULL,
    email    boolean NOT NULL,
    PRIMARY KEY (user_id, event)
);

-- Notifications show "New alert" and the like instead of client and device names.
ALTER TABLE users ADD COLUMN push_hide_details boolean NOT NULL DEFAULT false;

-- Pushes waiting to be sent, so the alert engine never waits on a push service.
CREATE TABLE push_outbox (
    id          bigserial PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    payload     jsonb NOT NULL,
    urgent      boolean NOT NULL DEFAULT false,
    attempts    integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now()
);
