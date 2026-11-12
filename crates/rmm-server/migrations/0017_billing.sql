-- Roadmap block 6 (PSA milestones 5-7): time, contracts and billing; scheduling, projects,
-- client documentation and reporting.
--
-- Money is bigint minor units (cents) with an ISO currency code; quantities are bigint
-- thousandths (1.5 hours = 1500), so nothing is ever a float.

-- ---------------------------------------------------------------------------
-- Settings
-- ---------------------------------------------------------------------------

ALTER TABLE company_settings
    ADD COLUMN currency            text NOT NULL DEFAULT 'USD' CHECK (currency ~ '^[A-Z]{3}$'),
    ADD COLUMN company_address     text NOT NULL DEFAULT '',
    ADD COLUMN invoice_prefix      text NOT NULL DEFAULT 'INV-',
    ADD COLUMN invoice_terms_days  integer NOT NULL DEFAULT 30 CHECK (invoice_terms_days BETWEEN 0 AND 365),
    ADD COLUMN invoice_footer      text NOT NULL DEFAULT '',
    -- Per hour, when nothing more specific applies.
    ADD COLUMN default_rate        bigint NOT NULL DEFAULT 0 CHECK (default_rate >= 0);

-- A client billed in another currency than the company's.
ALTER TABLE clients
    ADD COLUMN currency         text CHECK (currency ~ '^[A-Z]{3}$'),
    ADD COLUMN billing_address  text NOT NULL DEFAULT '',
    -- Customer ids in the accounting system, by provider: {"qbo": "58", "xero": "…"}.
    ADD COLUMN accounting_ids   jsonb NOT NULL DEFAULT '{}';

-- Invoices are emailed to these contacts.
ALTER TABLE contacts ADD COLUMN is_billing boolean NOT NULL DEFAULT false;

-- ---------------------------------------------------------------------------
-- Rates
-- ---------------------------------------------------------------------------

CREATE TABLE work_roles (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    -- Per hour.
    rate        bigint NOT NULL DEFAULT 0 CHECK (rate >= 0),
    created_at  timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE users
    ADD COLUMN work_role_id    uuid REFERENCES work_roles(id) ON DELETE SET NULL,
    -- Per hour: the technician's own billing rate (the last fallback), and what an hour of
    -- their time costs the MSP (for profitability).
    ADD COLUMN default_rate    bigint CHECK (default_rate >= 0),
    ADD COLUMN cost_rate       bigint NOT NULL DEFAULT 0 CHECK (cost_rate >= 0),
    -- Available hours a week, for utilisation.
    ADD COLUMN capacity_hours  integer NOT NULL DEFAULT 40 CHECK (capacity_hours BETWEEN 0 AND 168);

CREATE TABLE work_types (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    -- Per hour; NULL falls through to the work role or technician rate.
    rate        bigint CHECK (rate >= 0),
    billable    boolean NOT NULL DEFAULT true,
    active      boolean NOT NULL DEFAULT true,
    position    integer NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now()
);
INSERT INTO work_types (id, name, billable, position) VALUES
    (gen_random_uuid(), 'Remote support', true, 0),
    (gen_random_uuid(), 'Onsite', true, 1),
    (gen_random_uuid(), 'After hours', true, 2),
    (gen_random_uuid(), 'Project work', true, 3),
    (gen_random_uuid(), 'Internal', false, 4);

-- ---------------------------------------------------------------------------
-- Catalog
-- ---------------------------------------------------------------------------

CREATE TABLE products (
    id           uuid PRIMARY KEY,
    sku          text UNIQUE,
    name         text NOT NULL,
    description  text NOT NULL DEFAULT '',
    kind         text NOT NULL DEFAULT 'one_off' CHECK (kind IN ('one_off', 'recurring')),
    cost         bigint NOT NULL DEFAULT 0 CHECK (cost >= 0),
    price        bigint NOT NULL DEFAULT 0 CHECK (price >= 0),
    active       boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Contracts
-- ---------------------------------------------------------------------------

-- kind:
--   per_device      unit_price per enrolled agent (optionally only workstations or servers)
--   per_user        unit_price per user, user_count entered by hand
--   block_hours     unit_price buys block_minutes each cycle; time draws them down, the rest
--                   bills at overage_rate
--   time_materials  nothing recurring; all time is billable, at the contract's rate overrides
--   recurring       a flat fee (unit_price) plus contract_items each cycle
CREATE TABLE contracts (
    id                     uuid PRIMARY KEY,
    client_id              uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name                   text NOT NULL,
    kind                   text NOT NULL CHECK (kind IN ('per_device', 'per_user', 'block_hours', 'time_materials', 'recurring')),
    start_date             date NOT NULL,
    end_date               date,
    billing_cycle          text NOT NULL DEFAULT 'monthly' CHECK (billing_cycle IN ('monthly', 'quarterly', 'annual')),
    unit_price             bigint NOT NULL DEFAULT 0 CHECK (unit_price >= 0),
    device_filter          text NOT NULL DEFAULT 'all' CHECK (device_filter IN ('all', 'workstations', 'servers')),
    user_count             integer NOT NULL DEFAULT 0 CHECK (user_count >= 0),
    block_minutes          integer NOT NULL DEFAULT 0 CHECK (block_minutes >= 0),
    overage_rate           bigint CHECK (overage_rate >= 0),
    low_balance_minutes    integer NOT NULL DEFAULT 0 CHECK (low_balance_minutes >= 0),
    low_balance_warned_at  timestamptz,
    -- Work types this contract covers at no extra charge (per device / per user / recurring),
    -- or that draw from the bank (block hours). Anything else is billable on top.
    covered_work_type_ids  uuid[] NOT NULL DEFAULT '{}',
    -- Its tickets use this SLA policy (before the client's own).
    sla_policy_id          uuid REFERENCES sla_policies(id) ON DELETE SET NULL,
    -- The account manager (low-balance warnings).
    manager_id             uuid REFERENCES users(id) ON DELETE SET NULL,
    notes                  text NOT NULL DEFAULT '',
    created_at             timestamptz NOT NULL DEFAULT now(),
    CHECK (end_date IS NULL OR end_date >= start_date)
);
CREATE INDEX ON contracts (client_id);

CREATE TABLE contract_rate_overrides (
    contract_id   uuid NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    work_type_id  uuid NOT NULL REFERENCES work_types(id) ON DELETE CASCADE,
    rate          bigint NOT NULL CHECK (rate >= 0),
    PRIMARY KEY (contract_id, work_type_id)
);

-- Recurring lines billed every cycle (licences, a backup service).
CREATE TABLE contract_items (
    id              uuid PRIMARY KEY,
    contract_id     uuid NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    product_id      uuid REFERENCES products(id) ON DELETE SET NULL,
    description     text NOT NULL,
    quantity_milli  bigint NOT NULL CHECK (quantity_milli > 0),
    unit_price      bigint NOT NULL CHECK (unit_price >= 0),
    position        integer NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------------------
-- Time
-- ---------------------------------------------------------------------------

-- A technician's week (Monday). Entries in a submitted or approved week are locked.
CREATE TABLE timesheets (
    id            uuid PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    week_start    date NOT NULL CHECK (extract(isodow FROM week_start) = 1),
    status        text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'submitted', 'approved', 'rejected')),
    submitted_at  timestamptz,
    decided_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    decided_at    timestamptz,
    note          text NOT NULL DEFAULT '',
    UNIQUE (user_id, week_start)
);

CREATE TABLE time_entries (
    id               uuid PRIMARY KEY,
    user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id        uuid REFERENCES clients(id) ON DELETE CASCADE,
    ticket_id        uuid REFERENCES tickets(id) ON DELETE SET NULL,
    project_id       uuid,
    work_type_id     uuid NOT NULL REFERENCES work_types(id),
    started_at       timestamptz NOT NULL,
    -- NULL while the timer runs.
    ended_at         timestamptz,
    minutes          integer CHECK (minutes BETWEEN 0 AND 1440),
    billable         boolean NOT NULL DEFAULT true,
    note             text NOT NULL DEFAULT '',
    -- Worked out when the timesheet is approved: covered / block / billable / non_billable,
    -- the contract that applies, and the hourly rate and amount (minor units).
    coverage         text CHECK (coverage IN ('covered', 'block', 'billable', 'non_billable')),
    contract_id      uuid REFERENCES contracts(id) ON DELETE SET NULL,
    rate             bigint,
    amount           bigint,
    -- Set once billed; the entry is locked then.
    invoice_line_id  uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX time_entries_one_timer ON time_entries (user_id) WHERE ended_at IS NULL;
CREATE INDEX ON time_entries (user_id, started_at);
CREATE INDEX ON time_entries (client_id, started_at);
CREATE INDEX ON time_entries (ticket_id) WHERE ticket_id IS NOT NULL;
CREATE INDEX ON time_entries (project_id) WHERE project_id IS NOT NULL;

ALTER TABLE ticket_events DROP CONSTRAINT ticket_events_kind_check;
ALTER TABLE ticket_events ADD CONSTRAINT ticket_events_kind_check CHECK (kind IN (
    'created', 'reply', 'message', 'note', 'change', 'alert', 'job', 'session', 'merge', 'agent', 'sla', 'split', 'csat', 'time'));

-- Block-hours bank: purchases (+) when a cycle is invoiced, usage (-) when time is approved,
-- and manual adjustments.
CREATE TABLE contract_bank (
    id             bigserial PRIMARY KEY,
    contract_id    uuid NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    minutes        integer NOT NULL,
    reason         text NOT NULL CHECK (reason IN ('purchase', 'usage', 'adjustment')),
    time_entry_id  uuid REFERENCES time_entries(id) ON DELETE CASCADE,
    invoice_id     uuid,
    note           text NOT NULL DEFAULT '',
    created_by     uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON contract_bank (contract_id);

-- Products sold on a ticket (or to a client), billed on the next invoice.
CREATE TABLE charges (
    id               uuid PRIMARY KEY,
    client_id        uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    ticket_id        uuid REFERENCES tickets(id) ON DELETE SET NULL,
    product_id       uuid REFERENCES products(id) ON DELETE SET NULL,
    description      text NOT NULL,
    quantity_milli   bigint NOT NULL CHECK (quantity_milli > 0),
    unit_price       bigint NOT NULL CHECK (unit_price >= 0),
    unit_cost        bigint NOT NULL DEFAULT 0 CHECK (unit_cost >= 0),
    day              date NOT NULL DEFAULT current_date,
    invoice_line_id  uuid,
    created_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON charges (client_id) WHERE invoice_line_id IS NULL;

-- ---------------------------------------------------------------------------
-- Invoices
-- ---------------------------------------------------------------------------

-- draft → finalised → sent → paid, or void. A finalised invoice never changes and has a
-- number from `invoice_counter` (no gaps); corrections are credit notes.
CREATE TABLE invoices (
    id            uuid PRIMARY KEY,
    number        text UNIQUE,
    client_id     uuid NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
    kind          text NOT NULL DEFAULT 'invoice' CHECK (kind IN ('invoice', 'credit_note')),
    credit_of     uuid REFERENCES invoices(id) ON DELETE RESTRICT,
    currency      text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
    status        text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'finalised', 'sent', 'paid', 'void')),
    issue_date    date NOT NULL DEFAULT current_date,
    due_date      date NOT NULL DEFAULT current_date,
    period_start  date,
    period_end    date,
    total         bigint NOT NULL DEFAULT 0,
    notes         text NOT NULL DEFAULT '',
    -- What the invoice was billed to, frozen at finalisation.
    bill_to       text NOT NULL DEFAULT '',
    pdf_key       text,
    finalised_at  timestamptz,
    sent_at       timestamptz,
    paid_at       timestamptz,
    voided_at     timestamptz,
    -- Accounting sync: {"provider": "xero", "id": "…", "synced_at": "…", "error": null}.
    external      jsonb NOT NULL DEFAULT '{}',
    created_by    uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON invoices (client_id, issue_date DESC);
CREATE INDEX ON invoices (status);

-- kind: recurring, devices, users, block, overage, time, product, manual
CREATE TABLE invoice_lines (
    id              uuid PRIMARY KEY,
    invoice_id      uuid NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    position        integer NOT NULL DEFAULT 0,
    kind            text NOT NULL CHECK (kind IN ('recurring', 'devices', 'users', 'block', 'overage', 'time', 'product', 'manual')),
    description     text NOT NULL,
    quantity_milli  bigint NOT NULL,
    unit_price      bigint NOT NULL,
    amount          bigint NOT NULL,
    contract_id     uuid REFERENCES contracts(id) ON DELETE SET NULL,
    product_id      uuid REFERENCES products(id) ON DELETE SET NULL,
    -- Snapshots: device counts by OS, the billed period, the time entries' hours.
    details         jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX ON invoice_lines (invoice_id, position);

ALTER TABLE time_entries ADD CONSTRAINT time_entries_invoice_line FOREIGN KEY (invoice_line_id) REFERENCES invoice_lines(id) ON DELETE SET NULL;
ALTER TABLE charges ADD CONSTRAINT charges_invoice_line FOREIGN KEY (invoice_line_id) REFERENCES invoice_lines(id) ON DELETE SET NULL;
ALTER TABLE contract_bank ADD CONSTRAINT contract_bank_invoice FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE;

-- A contract's cycle appears on one invoice only (deleting the draft frees it).
CREATE TABLE contract_cycles (
    contract_id   uuid NOT NULL REFERENCES contracts(id) ON DELETE CASCADE,
    period_start  date NOT NULL,
    invoice_id    uuid NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    PRIMARY KEY (contract_id, period_start)
);

-- Gapless numbering: one row, locked while an invoice is finalised.
CREATE TABLE invoice_counter (
    id    integer PRIMARY KEY CHECK (id = 1),
    next  bigint NOT NULL
);
INSERT INTO invoice_counter (id, next) VALUES (1, 1001);

-- QuickBooks Online and Xero, over OAuth. Secrets and tokens are sealed with RMM_DATA_KEY.
CREATE TABLE accounting_connections (
    provider           text PRIMARY KEY CHECK (provider IN ('qbo', 'xero')),
    client_id          text NOT NULL DEFAULT '',
    client_secret      bytea,
    access_token       bytea,
    refresh_token      bytea,
    sealed             boolean NOT NULL DEFAULT false,
    token_expires_at   timestamptz,
    -- QuickBooks realm (company) id, or Xero tenant id.
    tenant_id          text,
    tenant_name        text,
    -- Where lines are booked: {"item_id": "1"} (QuickBooks) or {"account_code": "200", "tax_type": "OUTPUT"} (Xero).
    settings           jsonb NOT NULL DEFAULT '{}',
    oauth_state        text,
    connected_by       uuid REFERENCES users(id) ON DELETE SET NULL,
    connected_at       timestamptz,
    last_sync_at       timestamptz,
    last_error         text
);

-- ---------------------------------------------------------------------------
-- Scheduling, projects, documentation
-- ---------------------------------------------------------------------------

CREATE TABLE projects (
    id              uuid PRIMARY KEY,
    client_id       uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name            text NOT NULL,
    description     text NOT NULL DEFAULT '',
    status          text NOT NULL DEFAULT 'planned' CHECK (status IN ('planned', 'active', 'on_hold', 'done', 'cancelled')),
    budget_minutes  integer NOT NULL DEFAULT 0 CHECK (budget_minutes >= 0),
    start_date      date,
    due_date        date,
    owner_id        uuid REFERENCES users(id) ON DELETE SET NULL,
    contract_id     uuid REFERENCES contracts(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON projects (client_id);
ALTER TABLE time_entries ADD CONSTRAINT time_entries_project FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE SET NULL;

CREATE TABLE project_tasks (
    id                uuid PRIMARY KEY,
    project_id        uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    phase             text NOT NULL DEFAULT '',
    title             text NOT NULL,
    status            text NOT NULL DEFAULT 'todo' CHECK (status IN ('todo', 'doing', 'done')),
    estimate_minutes  integer NOT NULL DEFAULT 0 CHECK (estimate_minutes >= 0),
    assignee_id       uuid REFERENCES users(id) ON DELETE SET NULL,
    ticket_id         uuid REFERENCES tickets(id) ON DELETE SET NULL,
    due_date          date,
    position          integer NOT NULL DEFAULT 0,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON project_tasks (project_id, position);
ALTER TABLE tickets ADD COLUMN project_id uuid REFERENCES projects(id) ON DELETE SET NULL;

CREATE TABLE schedule_entries (
    id          uuid PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    starts_at   timestamptz NOT NULL,
    ends_at     timestamptz NOT NULL CHECK (ends_at > starts_at),
    title       text NOT NULL DEFAULT '',
    ticket_id   uuid REFERENCES tickets(id) ON DELETE CASCADE,
    project_id  uuid REFERENCES projects(id) ON DELETE CASCADE,
    notes       text NOT NULL DEFAULT '',
    created_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON schedule_entries (user_id, starts_at);
CREATE INDEX ON schedule_entries (starts_at);

-- Per-client documentation pages (network layout, vendors, procedures), with history.
CREATE TABLE client_docs (
    id          uuid PRIMARY KEY,
    client_id   uuid NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    title       text NOT NULL,
    category    text NOT NULL DEFAULT '',
    body        text NOT NULL DEFAULT '',
    updated_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON client_docs (client_id, lower(category), lower(title));
CREATE TABLE client_doc_revisions (
    id         bigserial PRIMARY KEY,
    doc_id     uuid NOT NULL REFERENCES client_docs(id) ON DELETE CASCADE,
    title      text NOT NULL,
    body       text NOT NULL,
    edited_by  uuid REFERENCES users(id) ON DELETE SET NULL,
    edited_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON client_doc_revisions (doc_id, id DESC);

-- Outbound mail can carry stored files (invoice PDFs): [{"name", "content_type", "key"}].
ALTER TABLE email_messages ADD COLUMN files jsonb NOT NULL DEFAULT '[]';
