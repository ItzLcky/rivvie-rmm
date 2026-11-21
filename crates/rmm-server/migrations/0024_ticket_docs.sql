-- Documentation pages linked to tickets (docs/design/documentation.md, "Documents on tickets"),
-- the same way agents are: the page must belong to the ticket's client, and each link and
-- unlink is an internal `doc` event on the timeline.
CREATE TABLE ticket_docs (
    ticket_id  uuid NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
    doc_id     uuid NOT NULL REFERENCES client_docs(id) ON DELETE CASCADE,
    added_by   uuid REFERENCES users(id) ON DELETE SET NULL,
    added_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (ticket_id, doc_id)
);
CREATE INDEX ON ticket_docs (doc_id);

ALTER TABLE ticket_events DROP CONSTRAINT ticket_events_kind_check;
ALTER TABLE ticket_events ADD CONSTRAINT ticket_events_kind_check CHECK (kind IN (
    'created', 'reply', 'message', 'note', 'change', 'alert', 'job', 'session', 'merge', 'agent', 'sla', 'split', 'csat', 'time', 'doc'));
