-- White-labelling (docs/design/branding.md). One row for the instance (client_id NULL) and
-- at most one per client, which overrides what that client's people see (the portal after
-- sign-in, emails to its contacts, the consent prompt on its devices). Every column but the
-- keys is optional: a NULL falls back to the instance row, then to the built-in default.

CREATE TABLE branding (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       uuid REFERENCES clients(id) ON DELETE CASCADE,
    product_name    text CHECK (length(product_name) BETWEEN 1 AND 60),
    -- Storage keys of the uploaded images (PNG or JPEG, at most 512 KiB).
    logo_light      text,
    logo_dark       text,
    icon            text,
    accent          text CHECK (accent ~ '^#[0-9a-f]{6}$'),
    support_email   text,
    support_phone   text,
    support_url     text,
    support_hours   text,
    email_from_name text,
    email_footer    text,
    updated_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT branding_client UNIQUE NULLS NOT DISTINCT (client_id)
);

INSERT INTO branding (client_id) VALUES (NULL);

-- The sender name is chosen when a message is queued (a client's own branding for mail to
-- its contacts); NULL means the instance's, as before.
ALTER TABLE email_messages ADD COLUMN from_name text;
