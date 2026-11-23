# Automation policies

Built in roadmap block 3 (Track 7, migration `0030_automations.sql`). The sixth module of the
[policy sets](policies.md): an `automation` item runs a saved script when something happens on a
device, or once on every device. API in [policies-api.md](policies-api.md#automations).

## Triggers

One trigger and one script per item (`config.trigger`):

| Trigger | Fires | Parameter |
|---|---|---|
| `enrollment` | the first time a device connects (`agents.first_connected_at`), once ever | none |
| `agent_online` | a device connects after being offline for `offline_minutes` (5 to 30 days) or more | `offline_minutes` |
| `alert_opened` | an alert of `alert_kind` opens on a device and isn't held back by a mute (an alert that opens muted fires when the mute ends with it still open, like `run_script_id`) | `alert_kind`: `offline`, `cpu`, `memory`, `disk`, `service`, `job_failed`, `log`, `security`, `patch` |
| `patch_reboot_pending` | a patch install finished and the machine still needs a restart (not when the agent is restarting by itself) | none |
| `run_once` | every device that uses the item's set or one below it, inside the item's limit, including devices that join later, once each | none |

A trigger on custom field or tag changes is left out: those models aren't in this build. The hook
point is [`automation::fire`](../../crates/rmm-server/src/automation.rs), the one entry point events
call, plus a new variant of `policy::Trigger` and of the `automation_runs.trigger` check.

Like scheduled scripts, an automation can be added to any set, limited to a client or site, with
devices left out. A set below may override `args`, `timeout_secs`, `retry_failed`, `max_attempts`,
`retry_minutes`, `cooldown_minutes`, `max_runs_per_hour`, `respect_window` and `enabled`; the
trigger, script, its parameters and `retain_days` are the item's own. A client's own script can
only be used by an item limited to that client.

## What a run is

Each run is a row of `automation_runs` and one job (`jobs.schedule_id` is the item, so Jobs names
the automation and the job output retention follows `retain_days`). The row's `status`:

- `waiting`: held back, starts when it can (`reason`: `maintenance_window`, `rate_limited`)
- `pending`: its job is queued or running (an offline device collects it when it reconnects)
- `succeeded` / `failed`: the job's outcome (`reason` for a failure is the job's own end: `failed`,
  `timed_out`, `lost`, `error`, `cancelled`, or `script_missing`, `script_other_client`)
- `skipped`: not run, `reason` says why (`cooldown`, `rate_limited`, `expired`, `no_longer_applies`)

`enrollment` and `run_once` have a unique row per (item, agent) (a partial unique index): that row
is the record that the script ran, so neither can run twice however often the event repeats or the
worker ticks. Event triggers add a row per event. Event rows are deleted after `retain_days`;
once-per-device rows stay.

**Run once, per device.** A worker (every 15 s) starts a run for each device an enabled run-once
item reaches that has no row yet. Status per device is on the item (`GET /policy-items/{id}/runs`,
shown as the *Devices* table). `retry_failed` runs a failure again after `retry_minutes`, up to
`max_attempts` runs in all (`enrollment` too); a cancelled run isn't retried. **Reset**
(`POST /policy-items/{id}/runs/reset`, admins for MSP-wide items, technicians with access for client
items) deletes the rows of some or all devices (or only the failed ones), except runs in progress, so
the worker starts them again. Moving a device to a set with a different run-once item runs that one.

## Safeguards against storms

All checked in the transaction that records the run, under an advisory lock per item, so two events
can't take the same slot:

- **Cooldown** (`cooldown_minutes`, default 60, event triggers): the same device doesn't run the
  automation again within it. The event is recorded as `skipped` (at most one skipped row per
  device, item and reason an hour, so a flapping device doesn't flood the table).
- **Hourly limit** (`max_runs_per_hour`, default 100, per automation across all devices): event runs
  over it are `skipped: rate_limited`; `enrollment` and `run_once` runs `wait` for a free slot, so
  none is lost.
- **Maintenance window** (`respect_window`): outside the device's site's maintenance window (the
  one patching uses; a site without a window is always open) the run waits and starts when it opens.
  Event runs that wait for more than 24 hours expire (`skipped: expired`).
- **Restart grace.** For `agent_online`, offline time is counted from the server's start for the
  first `RMM_AUTOMATION_RESTART_GRACE_MINUTES` (default 10) after it starts: the server can't know a
  device was offline while the server itself was down, and a restart must not fire every automation.
- A run is skipped when the item has stopped applying to the device (disabled, left out, moved) by
  the time it would start, and fails (`script_missing`) when its script was deleted.

## Where things are

- Rust: `src/automation.rs` (events, gates, worker), `policy::AutomationConfig`/`Trigger`,
  `api/automations.rs`. Hooks: `agent_ws` (connect, job finished), `alerts::announce` (alert opened),
  `patches::ingest_result` (reboot pending).
- Web: *Automations* section of a policy set (`AutomationForm`, `AutomationRuns`), *Automation
  history* on the device's Policy tab (`AutomationHistory`).
- Public API: `GET /agents/{id}/automations` (group `jobs`).
