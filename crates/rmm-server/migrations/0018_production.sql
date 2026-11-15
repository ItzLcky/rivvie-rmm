-- Production readiness (docs/design/production-readiness.md).

-- Download links for ticket attachments too large to email, sent to recipients who can't
-- sign in to the portal. The token is random; only its hash is kept, as for CSAT surveys.
CREATE TABLE attachment_links (
    token_hash    bytea PRIMARY KEY,
    attachment_id uuid NOT NULL REFERENCES ticket_attachments(id) ON DELETE CASCADE,
    expires_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON attachment_links (attachment_id);
CREATE INDEX ON attachment_links (expires_at);
