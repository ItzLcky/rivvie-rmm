-- Ticket templates with checklists (docs/design/identity.md#ticket-templates): onboarding and
-- offboarding as a ticket whose checklist items can be bound to identity actions on the
-- ticket's directory user.

CREATE TABLE ticket_templates (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    -- Offered only for this client when set.
    client_id   uuid REFERENCES clients(id) ON DELETE CASCADE,
    board_id    uuid REFERENCES boards(id) ON DELETE SET NULL,
    type_id     uuid REFERENCES ticket_types(id) ON DELETE SET NULL,
    priority    smallint NOT NULL DEFAULT 3 CHECK (priority BETWEEN 1 AND 4),
    subject     text NOT NULL DEFAULT '',
    body        text NOT NULL DEFAULT '',
    -- [{"text": "...", "action": null | "identity.disable" | ...}]
    checklist   jsonb NOT NULL DEFAULT '[]',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ticket_checklist_items (
    id            uuid PRIMARY KEY,
    ticket_id     uuid NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    position      integer NOT NULL,
    text          text NOT NULL,
    action        text CHECK (action IN ('identity.disable', 'identity.reset_password', 'identity.remove_groups', 'identity.revoke_sessions')),
    -- The action's outcome: NULL (not run), 'done' or 'failed: <why>'.
    action_state  text,
    done_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    done_at       timestamptz
);
CREATE INDEX ON ticket_checklist_items (ticket_id, position);

-- The directory user a ticket is about (a starter or a leaver).
ALTER TABLE tickets ADD COLUMN identity_user_id uuid REFERENCES identity_users(id) ON DELETE SET NULL;

INSERT INTO ticket_templates (id, name, priority, subject, body, checklist) VALUES
(gen_random_uuid(), 'New starter', 3, 'New starter: {name}',
 'Set up a new member of staff.',
 '[{"text": "Confirm start date, role and manager"},
   {"text": "Set an initial password and send it to the manager", "action": "identity.reset_password"},
   {"text": "Add to the right groups"},
   {"text": "Assign a licence and mailbox"},
   {"text": "Prepare and enroll a device"}]'),
(gen_random_uuid(), 'Leaver', 2, 'Leaver: {name}',
 'Offboard a member of staff who is leaving.',
 '[{"text": "Confirm the leaving date with the client"},
   {"text": "Disable the account", "action": "identity.disable"},
   {"text": "Sign out of every session", "action": "identity.revoke_sessions"},
   {"text": "Remove from groups", "action": "identity.remove_groups"},
   {"text": "Reset the password", "action": "identity.reset_password"},
   {"text": "Collect equipment and convert or forward the mailbox"}]');
