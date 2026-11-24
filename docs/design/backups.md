# Backup monitoring

The agent reads the last result of the backup jobs already on the machine and the server alerts when one failed or hasn't succeeded for too long. Monitoring only: nothing is started, configured or restored. Parity plan section C2; it rides on the [check runner](uptime.md#the-check-runner).

## How it is set up

A `backup` alert item in a policy set (the device's own, unlike uptime) is also a check: every device the item reaches gets a `CheckKind::Backup { providers, sources }` with the item's id, run every hour (timeout 5 minutes), as log watchers are derived from `log` items. `POST /agents/{id}/backups/check` reads them now (technician, audited `backup.check`; an addition to the plan, used by the device's card and the e2e).

Params: `{providers: ["auto"], sources: [{provider, env_file, repo, path, glob}], jobs: ["*"], max_age_hours: 26, warning_is_failure: false, require: false}`.

## Providers

| Provider | Read from |
|---|---|
| `wsb` | `Get-WBSummary` as JSON (PowerShell 5.1's `/Date(ms)/` dates and ISO dates); without the cmdlets, the `Microsoft-Windows-Backup` event log: event 4 is a finished backup, an error-level event a failure, event 1 (started) a running one. Installed and never run reports no job. |
| `veeam` | The `Veeam Backup` and `Veeam Agent` event logs through `wevtutil`, event 190 ("job finished"). The job name and result come from named data (`JobName`, `Result`), else the unnamed values, else the message ("Backup job 'X' finished with Y"), because the event's layout differs between products and versions. No Veeam PowerShell module. |
| `restic` | `restic snapshots --latest 1 --json --no-lock`; the newest snapshot is the last success. |
| `borg` | `borg list --last 1 --json --bypass-lock`; borg's times are local. |
| `timemachine` | `tmutil latestbackup` (its folder name is the local time), `tmutil status` (running), and `AutoBackup` from `com.apple.TimeMachine`'s preferences. |
| `file_age` | The newest file matching a glob under a folder (three levels, 20,000 entries), for products that leave files behind. |
| `auto` | `wsb` and `veeam` when their services exist (`wbengine`, `VeeamBackupSvc`, `VeeamEndpointBackupSvc`); `timemachine` on a Mac. |

restic and borg read an **env file already on the machine** (`RESTIC_REPOSITORY`, `RESTIC_PASSWORD_FILE`, `BORG_REPO`, `BORG_PASSCOMMAND`...): no secret comes from the server. restic and borg record only finished snapshots, so "failed" there means the repository couldn't be read; a backup that stopped running shows as stale. Repository locations are shown without credentials.

Paths and env files must be absolute and without `..` (checked by the server and again by the agent); on Unix the env file must be owned by root or the agent's own user and not writable by others, so a local user can't plant one. Tools run without a shell, with a timeout. Debug builds: `RMM_BACKUP_FAKE=<file>` reports the jobs in that JSON file while it exists.

## Data and alerts

Migration `0042_backups.sql`: `backup_jobs`, primary key `(agent_id, provider, job)`, with `last_run_at`, `last_success_at`, `last_result` (`success`/`warning`/`failed`/`running`/`unknown`), `message`, `size_bytes`, `updated_at`. Jobs not reported for 30 days are dropped.

Each report is checked against its item, using the jobs in that report: a job the item covers (its providers, `auto` meaning any, and its job patterns) that **failed** (or finished with warnings, with `warning_is_failure`) or is **stale** (no success within `max_age_hours`) opens `backup:<provider>:<job>`; with `require`, finding no job at all opens `backup:none`. Anything else clears. A policy change re-checks against the stored jobs. Backup alerts are the device's own: they count towards its health, and `backup` is in the automations' `ALERT_KINDS`, so an automation can react.

## API and UI

`GET /backups?client_id&result&provider&alerting&q` (keyset-paged, sortable by result, last success, last run, hostname, job) and `GET /agents/{id}/backups`; both in the public API under `agents` (`listBackups`, `listAgentBackups`). Live events: `backups`. Dashboard: `/backups` (Monitoring, `g x`), a Backups card on the device overview (shown when it has jobs), the `Backups` kind with a sources editor in the alert form, and a "Backup success" block in the QBR.

## Not proven here

The WSB, Veeam and Time Machine parsers are tested against fixtures written from the products' documented output, not recorded on real installs; restic and borg run for real only where they are installed (CI installs restic). See [windows-testing.md](windows-testing.md).
