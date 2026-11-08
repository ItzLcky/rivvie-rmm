-- Per-client access control. Admins always see every client. Other users see every client
-- while all_clients is true (the default, so existing accounts are unchanged); otherwise
-- only the clients listed in user_clients.
ALTER TABLE users ADD COLUMN all_clients boolean NOT NULL DEFAULT true;

CREATE TABLE user_clients (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, client_id)
);
CREATE INDEX ON user_clients (client_id);

-- Scripts are MSP-wide (client_id NULL, editable by admins) or belong to one client
-- (editable by technicians with access to it, and only runnable on that client's agents).
-- Names are unique within each scope.
ALTER TABLE scripts ADD COLUMN client_id uuid REFERENCES clients(id) ON DELETE CASCADE;
ALTER TABLE scripts DROP CONSTRAINT scripts_name_key;
CREATE UNIQUE INDEX scripts_scope_name ON scripts (client_id, name) NULLS NOT DISTINCT;
