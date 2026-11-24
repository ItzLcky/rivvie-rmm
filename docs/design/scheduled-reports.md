# Scheduled and emailed reports

Design record, 2026-11-24. Status: built (parity plan D2). Migration `0045_report_schedules.sql`.

## What it does

Any of the four reports (service desk, utilisation, profitability, the QBR) is rendered as a PDF on a cron timetable in a time zone and emailed to users, client contacts and, for admins, other addresses. Each schedule keeps a history of its runs with the PDF each one sent, and can be sent now. Reports → **Scheduled** lists them; every report tab has a **Schedule…** button that opens the same drawer.

Out of scope: a report builder, CSV/XLSX, new report types, a portal download page.

## Data (`0045`)

- `report_schedules`: `name`, `report` (`service_desk`, `utilisation`, `profitability`, `qbr`), `client_id` (required for `qbr`, optional for `service_desk`, never for the other two), `params` (`{"range": ...}`), `cron`, `timezone`, `user_ids`, `contact_ids`, `extra_emails`, `subject`, `message`, `enabled`, `owner_id`, `next_run_at`, `last_run_at`, `last_status`, `last_error`.
- `report_runs`: `trigger` (`schedule` or `manual`), `started_at`, `finished_at`, `status` (`running`, `sent`, `failed`), `from_date`, `to_date`, `storage_key`, `file_name`, `bytes`, `recipients` (one entry per recipient: `queued`, or `skipped` with the reason), `error`, `started_by`.

Columns beyond the plan: `report_runs.trigger`, `finished_at`, `from_date`/`to_date`, `file_name` and `started_by` (the history needs them), and `report_schedules.created_at`/`updated_at`.

## Ranges

`params.range`, resolved when the run starts, in the schedule's time zone:

| Preset | Covers |
|---|---|
| `last_week` | Monday to Sunday of the week before this one |
| `last_month` | the calendar month before this one (the default, except for the QBR) |
| `last_quarter` | the calendar quarter before this one (the QBR's default) |
| `last_30_days` | the 30 days up to yesterday |

The reports' SQL compares those dates with timestamps in the database session's zone (UTC), as the on-screen reports do.

## Who gets what

A schedule runs **with its owner's access evaluated at run time** (`reports::load_user`, the same columns a session reads). The owner must still be an active technician or admin and still able to open the report: a lost `billing.read` (profitability), `billing.read`/`time.approve` (utilisation) or client fails the run with that reason, and nothing is mailed.

- **Users** must be able to open the report themselves, and for a report that covers several clients (profitability, an all-clients service desk report) see every client the owner sees. Checked at save (400) and at run (skipped, with the reason).
- **Contacts** only receive a QBR or a service desk report about their own client; profitability and utilisation never go to contacts (the table also has a CHECK for it). Checked at save and at run.
- **Other addresses** (`extra_emails`) are admin-only: saving them needs an admin (403 otherwise) on an admin's schedule, and at run time they are skipped when the owner is no longer an admin.
- Every recipient gets **their own message**, so contacts never see each other's or staff addresses. A run with nobody left to send to fails.

## Server

- `api/reports.rs` is split into `build_service_desk`, `build_utilisation`, `build_profitability` (the JSON the pages show, for a given `User`) and `build_qbr` (blocks), with `blocks_*` turning each into `pdf::Block`s and `render(st, user, kind, client, from, to) -> Rendered`. The plan named typed `Data` structs; the JSON view *is* the data here (a `serde_json::Value`), which kept the handlers byte-for-byte compatible.
- `Rendered::pdf` is the one place a report becomes a PDF (`pdf::report` with `email::brand`), so the branding track's header logo lands there and in `pdf.rs` only.
- `src/reports.rs`: `run()` every 30 s claims due rows (`FOR UPDATE SKIP LOCKED`, moved to `scheduler::next_run` first, so a failure doesn't repeat every tick), then `run_schedule` builds, stores the PDF at `reports/<run id>.pdf` in object storage and queues one outbox message per recipient with `email::queue_report` (modelled on `queue_invoice`, purpose `report`). The body is plain text from `reports::email_body`; the brand name comes from `email::brand`, so from-name and footer branding apply when that track changes it.
- A message the outbox records as failed at once (no mail server) fails the run with that reason.
- Runs and their PDFs are pruned after 400 days (checked hourly). Deleting a schedule deletes its runs and PDFs.
- Large PDFs: the outbox's existing over-the-cap handling applies (generated files have no attachment row, so they're listed as "ask us for a copy"). The four reports are tens of KB, far under the cap; links for generated files were left out.

## API

- `GET|POST /report-schedules`, `GET|PUT|DELETE /report-schedules/{id}`, `POST /report-schedules/{id}/run` (returns the run), `GET /report-schedules/{id}/runs` (latest 100), `GET /report-runs/{id}/download`.
- Technicians list and manage their own; admins all of them (others' read as 404). An admin editing someone's schedule keeps them as the owner, and the owner's access is what's checked.
- Audit: `report_schedule.create`, `.update`, `.delete`, `.run`, and `report.sent` for every run that went out (user `None` for timetable runs).
- Not in the public API.

## Tests

- Unit: ranges at month, quarter and year ends and across a time zone (31 December in UTC is already January in Auckland), leap February, weeks on a Monday and a Sunday; preset parsing; the contact and user rules; email addresses and the body.
- e2e (`billing` section, `scheduled_reports`): a QBR schedule's `next_run_at` is the 1st at 07:00 London; send now reaches the admin and client A's billing contact through the SMTP sink, each in their own message with a `%PDF` attachment and the schedule's message; the run's PDF downloads; contacts on profitability, utilisation, another client's QBR or an all-clients desk report are 400; a technician without `billing.read` is 403, and without admin rights can't add other addresses; with `billing.read` their schedule sends, after losing it the run is `failed` naming `billing.read` and nothing is mailed; a schedule made due runs on its own and moves on; disabling clears `next_run_at`; deleting removes the runs.
- Visual: the Scheduled tab and the drawer with history, light and dark, with axe.
