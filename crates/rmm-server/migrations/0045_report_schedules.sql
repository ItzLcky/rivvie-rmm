-- Scheduled and emailed reports (docs/design/scheduled-reports.md): one of the four reports as
-- a PDF on a cron timetable, mailed to users, client contacts and (admins only) other addresses.
-- A schedule runs with its owner's access as it is at run time.

CREATE TABLE report_schedules (
    id            uuid PRIMARY KEY,
    name          text NOT NULL,
    report        text NOT NULL CHECK (report IN ('service_desk', 'utilisation', 'profitability', 'qbr')),
    -- The client the report is about: required for a QBR, optional for the service desk report,
    -- never for utilisation and profitability (they cover every client the owner can see).
    client_id     uuid REFERENCES clients(id) ON DELETE CASCADE,
    -- {"range": "last_week" | "last_month" | "last_quarter" | "last_30_days"}
    params        jsonb NOT NULL DEFAULT '{}',
    cron          text NOT NULL,
    timezone      text NOT NULL DEFAULT 'UTC',
    user_ids      uuid[] NOT NULL DEFAULT '{}',
    contact_ids   uuid[] NOT NULL DEFAULT '{}',
    extra_emails  text[] NOT NULL DEFAULT '{}',
    subject       text NOT NULL DEFAULT '',
    message       text NOT NULL DEFAULT '',
    enabled       boolean NOT NULL DEFAULT true,
    owner_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    next_run_at   timestamptz,
    last_run_at   timestamptz,
    last_status   text CHECK (last_status IN ('sent', 'failed')),
    last_error    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CHECK (report <> 'qbr' OR client_id IS NOT NULL),
    CHECK (report NOT IN ('utilisation', 'profitability') OR client_id IS NULL),
    CHECK (report NOT IN ('utilisation', 'profitability') OR cardinality(contact_ids) = 0)
);
CREATE INDEX report_schedules_due ON report_schedules (next_run_at) WHERE enabled;
CREATE INDEX ON report_schedules (owner_id);

CREATE TABLE report_runs (
    id           uuid PRIMARY KEY,
    schedule_id  uuid NOT NULL REFERENCES report_schedules(id) ON DELETE CASCADE,
    -- schedule: its timetable; manual: "send now".
    trigger      text NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule', 'manual')),
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    status       text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'sent', 'failed')),
    from_date    date,
    to_date      date,
    -- The PDF in object storage.
    storage_key  text,
    -- The attachment's name, without `.pdf`.
    file_name    text,
    bytes        bigint,
    -- [{"kind": "user" | "contact" | "email", "id": ..., "email": ..., "status": "queued" | "skipped", "reason": ...}]
    recipients   jsonb NOT NULL DEFAULT '[]',
    error        text,
    started_by   uuid REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX ON report_runs (schedule_id, started_at DESC);
CREATE INDEX ON report_runs (started_at);
