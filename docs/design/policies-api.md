# Policy management: API as built

Companion to [policies.md](policies.md) (the model). Everything here is under `/api`, takes
and returns JSON, and needs a signed-in session. Errors are `{"error": "message"}` with:

| Status | When |
|---|---|
| 400 | Invalid input. Validation of a policy names the set whose merged config fails: `"in Acme · Linux servers: threshold must be 1-100 percent"`. |
| 403 | Not allowed (see Permissions). Remote access turned off by policy answers 403 with a message naming the set. |
| 404 | Doesn't exist, or belongs to a client the user can't see (never 403 for those). |
| 409 | Deleting something still in use (message names what uses it); a duplicate category name. |

Fixed ids:

| What | Id |
|---|---|
| All devices (root set) | `00000000-0000-4000-8001-000000000000` |
| Windows / Linux / macOS sets | `…8001-000000000001` / `…0002` / `…0003` |
| {Windows, Linux, macOS} × {workstations, servers} sets | `…8001-0000000000{11,12,21,22,31,32}` |
| The six built-in categories (same order) | `00000000-0000-4000-8002-0000000000{11,12,21,22,31,32}` |
| Patch item | `00000000-0000-4000-8000-000000000001` |
| Security item | `00000000-0000-4000-8000-000000000002` |
| Remote access item | `00000000-0000-4000-8000-000000000003` |
| Agent item | `00000000-0000-4000-8000-000000000004` |

## Permissions

- **Read**: anyone signed in. Lists are limited to the clients the user can see: MSP-wide sets
  are visible to all, a client's sets only to users who can see that client; items limited to
  a client the user can't see are left out everywhere (set views, agent view, schedules).
- **MSP-wide sets** (create, rename, move, delete, duplicate), **items without a client limit**
  (in any MSP-wide set, including the four single-instance items), **overrides held in an
  MSP-wide set**, and **device categories**: admin.
- **A client's sets**, **items limited to a client**, **overrides in a client's set**, **that
  client's assignments**, **pins**, **customize**, **category moves of its agents**, **exclusions**
  (also needs access to the agent): technician (or admin) with access to that client.
- Anything in the **`security` module** (the security item, its overrides) also needs the
  `security.manage` permission.
- Every mutation writes to the audit log (`policy_set.*`, `policy.*`, `device_category.*`,
  `policy_assignment.*`, `agent.category`, `agent.policy_pin`, `agent.policy_customize`).

## Shapes

### SetRow

```json
{
  "id": "uuid", "parent_id": "uuid | null", "client_id": "uuid | null", "client_name": "string | null",
  "name": "Acme · Linux servers", "description": "", "builtin": false,
  "depth": 3,                         // All devices = 0; max 8
  "devices": 12,                      // agents using it (of the clients the user can see)
  "items": 2, "overrides": 1,         // items defined here, overrides held here
  "defines": ["alert"],               // modules it defines items of
  "overrides_modules": ["patch"],     // modules it overrides
  "default_for": ["category uuid"],   // categories whose default set it is
  "created_at": "...", "updated_at": "..."
}
```

### ChainEntry

`{"id", "name", "client_id": "uuid | null", "builtin"}` — a set's place in the tree. Chains run
from All devices down.

### ItemView (one item as it applies in one set)

```json
{
  "id": "uuid", "module": "alert | schedule | software | automation | patch | security | remote_access | agent", "name": "CPU",
  "origin_set_id": "uuid", "origin_set_name": "Linux",
  "status": "defined | inherited | overridden",   // relative to the set being viewed
  "enabled": true, "config": { ... },             // merged, as it applies in this set
  "item_enabled": true, "item_config": { ... },   // as defined at the origin
  "sources": { "enabled": "set uuid", "severity": "set uuid", "params.threshold": "set uuid", ... },
                                                  // which set each leaf field's value comes from (dotted paths)
  "override": { "enabled": null, "config": { "params": { "threshold": 95 } }, "updated_at": "..." } | null,
                                                  // this set's override, if any (sparse)
  "limit": { "client_id": "uuid | null", "client_name": "...", "site_id": "uuid | null", "site_name": "...",
             "excluded": [{ "id": "agent uuid", "hostname": "..." }] },
  "editable": true,        // may edit the item at its origin
  "overridable": true,     // may override it in the set being viewed (false at the origin)
  "open_alerts": 0,        // unresolved alerts it raised (agent view: on that agent)
  "schedule": { "next_run_at": "... | null", "last_run_at": "... | null" } | null,  // schedules only
  "applies": true,         // agent view only: the limit includes the agent
  "excluded": false        // agent view only
}
```

### Module configs

Stored complete at the item; overrides hold only the fields that differ. Merge rule: objects
merge key by key, recursively; scalars, arrays and `null` replace.

| Module | Config | Overridable below the origin |
|---|---|---|
| `alert` | `{kind, params, severity, channel_ids: [], notify_resolved: true, renotify_minutes: null, ticket_board_id: null, ticket_priority: 3, ticket_auto_resolve: false, run_script_id: null}` — `kind`/`params` as the old alert policies (`offline`, `cpu`, `memory`, `disk`, `service`, `job_failed`, `log`, `security`, `patch`) | everything but `kind` |
| `schedule` | `{script_id, cron, timezone: "UTC", args: [], timeout_secs: null, retain_days: 30}` | `args`, `timeout_secs` (and `enabled`) |
| `software` | `{package_id, state: "present" \| "latest" \| "absent", bootstrap_choco: false, window: null}` (see [software.md](software.md)) | `state`, `bootstrap_choco`, `window` (and `enabled`) |
| `automation` | `{trigger: "enrollment\|agent_online\|alert_opened\|patch_reboot_pending\|tag_added\|field_changed\|run_once", script_id, args: [], timeout_secs: null, offline_minutes: null, alert_kind: null, tag_id: null, field_id: null, field_value: null, retry_failed: false, max_attempts: 3, retry_minutes: 30, cooldown_minutes: 60, max_runs_per_hour: 100, respect_window: false, retain_days: 30}` — `offline_minutes` (5-43200) is required by `agent_online` and refused elsewhere, `alert_kind` likewise for `alert_opened`, `tag_id` for `tag_added` (an existing tag), `field_id` for `field_changed` (an existing field of devices; `field_value`, optional, is a value that field can hold), `retry_failed` only for `enrollment` and `run_once` | `args`, `timeout_secs`, `retry_failed`, `max_attempts`, `retry_minutes`, `cooldown_minutes`, `max_runs_per_hour`, `respect_window` (and `enabled`) |
| `patch` | `{auto_approve_severities: [], auto_approve_categories: [], deferral_days, auto_install, reboot_policy, window: null \| {days: [0-6], start: "HH:MM", minutes: 15-1440, tz: "Europe/Berlin" \| "site"}}` | all fields |
| `security` | `{sensor_enabled, quick_scan_hours, full_scan_days, auto_quarantine, prevention, canaries, telemetry_mb, realtime: "off\|audit\|block", scan_on_write, archive_depth, database_max_age_hours}` | all fields |
| `remote_access` | `{desktop_enabled, desktop_consent, shell_enabled, files_enabled}` | all fields |
| `agent` | `{auto_update}` | all fields |

Unknown fields are rejected (400). Alert and schedule items create with defaults filled in;
the response's `item_config` is the normalized form. The four single-instance modules exist
once, in All devices: they can't be created, deleted, disabled (`enabled` stays true, and an
override's `enabled` must be null), limited or excluded from.

## Policy sets

### `GET /policy-sets[?client_id=]`
→ `SetRow[]`, flat (build the tree from `parent_id`), built-ins first. `client_id`: only sets
that client's devices can use (MSP-wide ones and the client's own). 404 for an invisible client.

### `POST /policy-sets`
`{name, description?: "", parent_id, client_id?: uuid}` → `SetRow`.
A child of a client's set always belongs to that client (`client_id` defaults to it; another
client → 400). Depth over 8 → 400. Name 1-200 chars, description ≤ 2000. Permission by the new
set's owner (admin for MSP-wide).

### `GET /policy-sets/{id}`
→ `SetRow` fields plus:
```json
{ "chain": [ChainEntry...],      // All devices .. this set
  "children": [SetRow...],
  "policies": [ItemView...],     // every item reaching this set, as it applies here,
                                 // ordered alert, schedule, patch, security, remote_access, agent; then name
  "editable": true }             // may rename/move/delete it and add items to it
```

### `PUT /policy-sets/{id}`
`{name?, description?, parent_id?}` → `SetRow`. Moving takes everything below along; built-ins
can't move (400); can't move below itself (400); an MSP-wide set only below MSP-wide sets, a
client's set only below MSP-wide sets or its own client's (400); depth limit (400). After a
move, overrides of items that no longer reach their set are deleted, and every merged config is
validated (400 names the set).

### `DELETE /policy-sets/{id}`
→ `{"ok": true}`. Built-ins: 400. In use: 409 `"X is still used by 2 child sets, 1 assignment, 3 pinned devices, the default of Kiosks"`.
Its items go with it (their open alerts close quietly, `resolution: "policy"`).

### `POST /policy-sets/{id}/duplicate`
`{name?: "Copy of X", client_id?: uuid}` (body optional) → `SetRow` of the copy: a sibling (same
parent) with the set's own items (new ids, schedules get a fresh next run) and its overrides;
not the sets below it. `client_id` copies an MSP-wide set as that client's own (its items become
limited to the client; items limited to another client → 400). All devices can't be duplicated.

### `GET /policy-sets/{id}/agents`
Paged like `/agents` (`limit`, `after`, `before`, `sort=hostname|client`, `dir`) →
`{items: [{id, hostname, online, os_family, platform, client_id, client_name, site_id, site_name, category_id, category_name, reason: "pin|site|client|default"}], next, prev, total, total_exact}`.

## Items

### `POST /policy-sets/{set_id}/items`
`{module: "alert" | "schedule" | "software" | "automation", name, enabled?: true, config, client_id?, site_id?}` → `ItemView`
(at its set). In a client's set the limit is that client (another → 400). `site_id` must belong
to `client_id` (400). Referenced channels, boards and scripts must exist (404 / 400 "unknown
notification channel"); a client's own script (`run_script_id`, `params.script_id` of
`job_failed`, a schedule's `script_id`) needs the item limited to that client (400 "that script
belongs to another client"). Single-instance modules → 400.

### `GET /policy-items/{id}`
→ `ItemView` at its origin set (status `defined`). For links that know only the item, such as an
alert's `policy_id`; 404 like the set views for an item limited to a client the user can't see.

### `PUT /policy-items/{id}`
`{name?, enabled?, config?, client_id?: uuid|null, site_id?: uuid|null}` → `ItemView` at its
origin. Omitted fields are unchanged; `config` replaces the whole config (send the complete
object). An alert's `kind` can't change (400). Every merged config of every set the item reaches
is validated (400 names the set). A schedule's cron/timezone change moves its next run.

### `DELETE /policy-items/{id}`
→ `{"ok": true}`. Its open alerts close quietly first. Single-instance → 400.

### `PUT /policy-items/{id}/overrides/{set_id}`
`{enabled?: bool | null, config: {sparse}}` → `ItemView` in that set. Replaces the set's
override for the item. `enabled` null/omitted = as inherited. Only fields the module lets
descendants change (table above); others → 400. Empty objects are dropped; `{config: {},
enabled: null}` removes the override. The set must be strictly below the item's set (400), and
not another client's than the item's limit (400). Validation of every descendant's merged
config: 400 names the set. Per-field "Reset to inherited" = PUT the override without that field.

### `DELETE /policy-items/{id}/overrides/{set_id}`
"Reset all" → `ItemView` in that set (status `inherited`). Validated like a PUT (removing an
override can break a descendant's).

### `PUT /policy-items/{id}/exclusions/{agent_id}` / `DELETE` (same path)
Leave one agent out of an alert or schedule item, or put it back (no body) → `ItemView` at the
origin (`limit.excluded` lists it). Its open alerts from the item on that agent close quietly.

## Device categories

### `GET /device-categories`
→ `[{id, name, description, builtin, os_family: "windows|linux|macos" | null, platform: "workstation|server" | null, default_set_id, default_set_name, devices, created_at, updated_at}]`, built-ins first.

### `POST /device-categories` (admin)
`{name, description?, default_set_id}` → the row. The default set must be MSP-wide (400). Name
unique, case-insensitive (409).

### `PUT /device-categories/{id}` (admin)
`{name?, description?, default_set_id?}` → the row. Built-ins can't be renamed (400) but can get
another default set. Devices are re-resolved.

### `DELETE /device-categories/{id}` (admin)
→ `{"ok": true}`. Built-ins: 400. Its devices go back to automatic placement; its assignments
are deleted; enrollment tokens naming it no longer do.

### `POST /agents/category` (technician with access)
`{agent_ids: [uuid] (1-5000), category_id: uuid | null}` → `{changed, moved}` (`moved`: how many
now use a different set). `null` = automatic: the built-in category for the agent's OS and
platform, re-applied whenever it reports them. A category sets `category_manual`. Any agent the
user can't see → 404 (nothing changes).

## Assignments

### `GET /policy-assignments[?client_id=]`
→ `[{id, client_id, client_name, site_id: uuid|null, site_name, category_id, category_name, policy_set_id, policy_set_name, updated_at}]`.

### `PUT /policy-assignments`
`{client_id, site_id?: uuid, category_id, policy_set_id}` → the row. Upsert per (client, site,
category). The set must be MSP-wide or the client's own (400); the site must be the client's
(400). Agents are re-resolved at once.

### `DELETE /policy-assignments/{id}` → `{"ok": true}`.

Which set a device uses: its pin, else the (site, category) assignment, else the (client,
category) assignment, else the category's default set.

## One agent

### `GET /agents/{id}/policy`
```json
{ "agent_id": "uuid", "hostname": "web1", "client_id": "uuid", "site_id": "uuid",
  "platform": "workstation | server",
  "category": { "id": "uuid", "name": "Linux servers", "builtin": true, "manual": false },
  "set": ChainEntry,                          // the set it uses
  "reason": "pin | site | client | default",
  "assignment_id": "uuid | null",             // the assignment behind reason site/client
  "pin": ChainEntry | null,
  "chain": [ChainEntry...],                   // All devices .. its set
  "policies": [ItemView...] }                 // with `applies` and `excluded`
```

### `PUT /agents/{id}/policy-pin` (technician with access)
`{policy_set_id: uuid | null}` → the agent policy view above. The set must be MSP-wide or the
agent's client's (400). `null` unpins; the set stays (delete it separately).

### `POST /agents/{id}/policy-pin/customize` (technician with access)
No body → the agent policy view. Creates a client-owned child of the agent's current set named
after the host (description "Customized for <host>") and pins it.

## Elsewhere

- `GET /agents` items gain `platform`, `category_id`, `category_name`, `policy_set_id`,
  `policy_set_name`; filters `?category_id=` and `?policy_set_id=`; `sort=category`.
- `POST /sites/{id}/enrollment-tokens` takes `category_id` (404 unknown); token rows return
  `category_id`, `category_name`. Agents enrolled with it start in that category (manual).
- `GET /agents/{id}/patches` → `policy` is now `{id (patch item), set_id, source (set name),
  auto_approve_severities, auto_approve_categories, deferral_days, auto_install, reboot_policy,
  own_window, window: {days, start, minutes, tz, open_now, next_start}}` (`window` is what
  automatic installs use: the policy's own when `own_window`, else the site's).
- `GET /agents/{id}/security` → `policy` unchanged in shape (the agent's effective sensor policy).
- `GET /alerts`, `/alerts/{id}`: `policy_id`/`policy_name` are the alert item; rows gain
  `script_job_id` (the job `run_script_id` started when it opened, or null).
- `GET /schedules` (read-only list of every `schedule` item the user can see),
  `GET /schedules/{id}`: `{id, name, set_id, set_name, script_id, script_name, interpreter,
  client_id, client_name, site_id, site_name, cron, timezone, args, timeout_secs, retain_days,
  enabled (at its own set), agents (it runs on now), next_run_at, last_run_at, last_run:
  {status: count}, created_by_name, created_at, updated_at}`. Run history: `GET /jobs?schedule_id=`.
  `POST /schedules/{id}/run` (same permission as editing the item) → `{queued, sent, skipped}`.
  `GET /schedules/preview?cron=&timezone=` unchanged.
- `GET /agent-updates` → `auto_update` is All devices' agent item setting.
- Remote access: `GET /agents/{id}/desktop` and `/shell` (WebSocket upgrades) and the file
  tools (`/agents/{id}/files`, `/files/download`, `/files/upload`) answer 403 `"remote desktop is
  turned off for this device by policy set X"` (or the shell / file access equivalents).
  Remote desktop consent comes from `remote_access.desktop_consent`.

Removed: `/alert-policies*`, `/agents/{id}/alert-policies`, `/patch-policies*`,
`/security/policies*`, `POST /schedules`, `PUT|DELETE /schedules/{id}`,
`PUT /clients/{id}/desktop`; `desktop_consent` from `/clients` rows; `auto_update_agents` from
`/settings`.

## Automations

See [automations.md](automations.md). Items are created and edited like alert and schedule items
(`module: "automation"`; the limit, exclusions and overrides work the same, and the item's
`ItemView` carries `runs: {waiting, pending, succeeded, failed, skipped}` counts of the devices the
user can see). Run state:

- `GET /agents/{id}/automations` → the agent's 200 latest runs, newest first: `[{id, item_id,
  item_name, agent_id, hostname, trigger, status, reason, context, job_id, script_id, script_name,
  exit_code, attempts, created_at, started_at, finished_at}]`. Also a public API operation
  (`listAgentAutomations`, scope `jobs`, read).
- `GET /policy-items/{id}/runs?status=&q=&limit=` (visible items only; 404 unless it is an
  automation) → `{counts: {waiting, pending, succeeded, failed, skipped}, runs: [...]}`, limited to
  devices of the clients the user can see. For `enrollment` and `run_once` there is one row per device.
- `POST /policy-items/{id}/runs/reset` `{agent_ids?: [], failed_only?: false}` → `{reset: n}`.
  Run-once automations only (400 otherwise). Deletes the run records (not runs in progress) of those
  devices, or of every device the user can see, so they run again. Same permission as editing the
  item. Audit: `automation.reset`.
