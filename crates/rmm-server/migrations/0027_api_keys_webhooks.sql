-- API keys, service accounts and outbound webhooks (docs/design/api.md).

-- A service account is a user that can't sign in: its keys are what authenticate it. Its
-- password hash is the unusable value '!', and sign-in and admin password resets refuse it.
ALTER TABLE users ADD COLUMN service_account boolean NOT NULL DEFAULT false;

-- API keys authenticate `Authorization: Bearer rmm_k_...` on the public API (the routes in
-- `api::public`). Only the SHA-256 of the key is kept; `prefix` is the first characters, so
-- people can tell keys apart. A key acts as its owner but never with more: `access`, `scopes`
-- (resource groups), `permissions` (named permissions, see `auth::Perm`) and `client_ids` can
-- only narrow what the owner has, and are intersected with the owner's current rights on
-- every request.
CREATE TABLE api_keys (
    id                  uuid PRIMARY KEY,
    owner_id            uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name                text NOT NULL,
    prefix              text NOT NULL,
    token_hash          bytea NOT NULL UNIQUE,
    access              text NOT NULL CHECK (access IN ('read', 'write')),
    scopes              text[] NOT NULL,
    permissions         text[] NOT NULL DEFAULT '{}',
    -- NULL: every client the owner can see.
    client_ids          uuid[],
    rate_limit_per_min  integer NOT NULL DEFAULT 600 CHECK (rate_limit_per_min BETWEEN 1 AND 100000),
    expires_at          timestamptz,
    last_used_at        timestamptz,
    last_used_ip        text,
    revoked_at          timestamptz,
    revoked_by          uuid REFERENCES users(id) ON DELETE SET NULL,
    created_by          uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON api_keys (owner_id);

-- Outbound webhooks for ticket and alert events. `client_id` NULL subscribes to every client
-- (and to tickets with no client yet). The body is signed with `secret` like the webhook
-- notification channel: `X-RMM-Signature: sha256=<hex hmac of the body>`.
CREATE TABLE webhook_subscriptions (
    id              uuid PRIMARY KEY,
    name            text NOT NULL,
    url             text NOT NULL,
    -- Sealed with RMM_DATA_KEY when it's set (`crypto::store`).
    secret          bytea NOT NULL,
    secret_sealed   boolean NOT NULL DEFAULT false,
    client_id       uuid REFERENCES clients(id) ON DELETE CASCADE,
    events          text[] NOT NULL,
    -- Send internal notes (private ticket comments) too.
    internal_notes  boolean NOT NULL DEFAULT false,
    enabled         boolean NOT NULL DEFAULT true,
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- The outbox and the delivery log in one: rows are written in the transaction that changed the
-- ticket (or right after the alert changed), claimed and retried by the notification worker,
-- and kept for 30 days once they're no longer pending.
CREATE TABLE webhook_deliveries (
    id               bigserial PRIMARY KEY,
    subscription_id  uuid NOT NULL REFERENCES webhook_subscriptions(id) ON DELETE CASCADE,
    delivery_id      uuid NOT NULL DEFAULT gen_random_uuid(),
    event            text NOT NULL,
    payload          jsonb NOT NULL,
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
    attempts         integer NOT NULL DEFAULT 0,
    next_attempt_at  timestamptz NOT NULL DEFAULT now(),
    last_error       text,
    response_status  integer,
    duration_ms      integer,
    created_at       timestamptz NOT NULL DEFAULT now(),
    sent_at          timestamptz
);
CREATE INDEX webhook_deliveries_due ON webhook_deliveries (next_attempt_at) WHERE status = 'pending';
CREATE INDEX ON webhook_deliveries (subscription_id, id DESC);
CREATE INDEX ON webhook_deliveries (created_at);
