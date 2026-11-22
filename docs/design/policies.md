# Policy management

Design record, 2026-11-18. Status: built (steps 1-6: server, agent, API, e2e, web, docs). The API as built is in [policies-api.md](policies-api.md); where the build departed from
this design, the text below says so and [As built](#as-built) lists every change.

Modelled on SuperOps "Advanced Policy" (device categories, a tree of policy sets with
inheritance and overrides, per-client association, "one device, one policy set"), with the
changes listed under [Differences from SuperOps](#differences-from-superops).

## Why

Today there are four unrelated policy mechanisms, each with its own scoping rules:

| What | Table | Scope model |
|---|---|---|
| Alert policies | `alert_policies` | Additive. MSP-wide, client or site, optional OS, `excluded_agents` |
| Patch policy | `patch_policies` | Most specific of site / client / MSP-wide applies, whole |
| Sensor policy | `security_policies` | Same as patch |
| Scheduled scripts | `schedules` | Additive. MSP-wide, client or site, optional OS |

Plus two settings that are policies in all but name: `clients.desktop_consent` and
`company_settings.auto_update_agents`.

Nothing can tell servers from workstations, nothing inherits, and a technician can't answer
"what applies to this machine, and why?" in one place. This design replaces all of the above
with one model.

## Model

### Device categories

A category is a named folder of devices with no filter conditions. Every agent is in exactly
one.

- Six built-in categories: {Windows, Linux, macOS} × {workstation, server}. They can't be
  renamed or deleted. (`os_family = 'other'` agents go to Linux server.)
- Custom categories (name, description, and a **default policy set**, required). Used for
  "Kiosks", "SQL servers", "Lab machines".
- An agent is placed in the built-in category for its OS and platform when it enrolls, and
  again on each connect while `category_manual` is false. A technician can move agents to any
  category (single or bulk), which sets `category_manual`. Deleting a custom category puts its
  agents back on automatic.
- An enrollment token may name a custom category; agents enrolled with it start there
  (manual). This is our version of SuperOps's per-category install script.

**Platform** (workstation / server) is new. The agent reports it in `SystemInfo`
(`platform: Option<Platform>`, `#[serde(default)]` so old agents still parse):

- Windows: `HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions\ProductType`; `WinNT` is a
  workstation, anything else a server.
- Linux: workstation if the DMI chassis type is portable (8, 9, 10, 11, 14, 30, 31, 32) or the
  default systemd target is `graphical.target`; otherwise server.
- macOS: workstation.

The server stores it in `agents.platform` (NOT NULL). When an agent doesn't report it, the
server falls back to the old `billing::is_server` heuristic, now the SQL function
`policy_platform(os_family, os_name)`: Linux, or an OS name containing "server", is a server
(so an `other`-OS agent counts as a workstation, as billing counted it, while its category is
Linux servers). Billing's server/workstation counts use `agents.platform`. The server learns the
platform at enrollment and from every inventory (the server requests one on every connect), so
already-enrolled agents are classified after they self-update. The Linux agent reads the
`default.target` link instead of running `systemctl get-default`.

### Policy sets

A policy set is a collection of policies. Sets form one tree.

Ten built-in sets, fixed ids, can't be deleted or moved (they can be renamed):

```
All devices
├── Windows
│   ├── Windows workstations
│   └── Windows servers
├── Linux
│   ├── Linux workstations
│   └── Linux servers
└── macOS
    ├── macOS workstations
    └── macOS servers
```

Each built-in category's default set is the matching leaf. Custom sets are children of any
set, to any depth (cap depth at 8). A set has `client_id NULL` (MSP-wide) or belongs to one
client; a client's set can only be assigned to that client's devices, and its children must
belong to the same client.

Deleting a set: built-ins never; otherwise only when it has no children, no assignment, no
pin and isn't a category default. The API answers 409 naming what still uses it.

### Which set a device uses

Exactly one, the first that exists of:

1. The agent's **pin** (`agents.policy_pin_id`): a single-device exception.
2. An assignment for (the agent's site, its category).
3. An assignment for (the agent's client, its category).
4. The category's default set.

Assignments are rows `(client_id, site_id NULL, category_id) → policy_set_id`, unique per
scope. The result is stored in `agents.policy_set_id` (NOT NULL) and kept right by a trigger
on `agents` (site, category or pin changed) plus a bulk re-resolve when assignments, category
defaults or sets change.

"Customize for this device" on the agent page creates a client-owned child of the agent's
current set, named after the host, and pins it. Unpinning leaves the set in place (delete it
separately); the UI offers both.

### Policies (items) and modules

A policy is an item in a set: `(id, set_id, module, name, enabled, config jsonb)`.

| Module | Instances | Config (v1) | Replaces |
|---|---|---|---|
| `alert` | many | `kind`, `params`, `severity`, `channel_ids`, `notify_resolved`, `renotify_minutes`, the ticket fields, `run_script_id` | `alert_policies` |
| `schedule` | many | `script_id`, `cron`, `timezone`, `args`, `timeout_secs`, `retain_days` | `schedules` |
| `patch` | one | `auto_approve_severities`, `auto_approve_categories`, `deferral_days`, `auto_install`, `reboot_policy`, `window` | `patch_policies` |
| `security` | one | every column of `security_policies` | `security_policies` |
| `remote_access` | one | `desktop_enabled`, `desktop_consent`, `shell_enabled`, `files_enabled` | `clients.desktop_consent` |
| `agent` | one | `auto_update` | `company_settings.auto_update_agents` |
| `automation` | many | `trigger`, `script_id`, `args`, `timeout_secs`, trigger parameters, retry and safeguard settings | (new, [automations.md](automations.md)) |

- **Single-instance modules** exist exactly once, as an item in *All devices*, seeded with
  today's defaults. They can't be deleted or added elsewhere; every other set can only
  override fields. This removes SuperOps's "a descendant already has one" conflict rules.
- **Multi-instance modules** (`alert`, `schedule`) can be defined in any set and apply to that
  set and all its descendants.
- Alert and schedule items keep an optional **limit**: `client_id`, `site_id` (as today) and
  `excluded_agents` (alerts and schedules). An item in a client's set is always limited to that
  client. An item applies to an agent when the agent's set is the item's
  set or a descendant, *and* the agent is inside the limit. The limit is part of the item
  and can't be overridden. This keeps "one extra alert for Acme" a single item instead of six
  child sets, and keeps today's technician permissions meaningful.
- `patch.window`: `null` uses the site's maintenance window (today's behaviour); otherwise
  `{days, start, minutes, tz}` with `tz: "site"` allowed. This is what lets servers and
  workstations at one site patch at different times.
- `alert.run_script_id`: optional script run once on the agent when the alert opens (not when
  it opens suppressed; when a mute ends with it still open, it runs then). The job is linked
  from the alert by `alerts.script_job_id` (returned as `script_job_id`). Self-healing, from
  roadmap block 5.
- `remote_access` is enforced by the server where sessions start (`desktop_ws`, `shell_ws`,
  the file tools: list, download, upload): a disabled feature answers 403 with a message naming
  the policy set. Single-instance items are always enabled; only their fields can be overridden.
- `agent.auto_update` replaces the company-wide switch in the automatic rollout query.
- A `software` module is reserved for roadmap block 7 and not built now.

### Inheritance and overrides

- An item applies downward only. Nothing propagates upward.
- A descendant set may hold one **override** per inherited item: `(item_id, set_id, enabled
  NULL, config jsonb)`. `config` is sparse: only the fields that differ. `enabled NULL`
  means "as inherited".
- The effective config for a set is the item's config with every override on the path from
  the item's set down to this set merged in order. Merge rule: objects merge key by key,
  recursively; everything else (scalars, arrays, `null`) replaces. So one alert threshold
  inside `params`, or just `reboot_policy`, can be overridden on its own.
- `kind` (alerts) and `script_id` (schedules) can't be overridden. For schedules, v1 allows
  overriding only `enabled`, `args` and `timeout_secs`: one cron clock per item.
- Reverting: delete a field from the override (per-field "Reset to inherited"), or delete the
  override row ("Reset all").
- Every write is validated against every set it affects: if the merged config of any
  descendant no longer validates (`Rule::parse` and the module's own checks), the write is
  rejected with a 400 naming the set.

### Materialized state

Hot paths (alert evaluation, connect, patch scheduling) must not walk the tree.

- `policy_effective (set_id, item_id, module, enabled, config, PRIMARY KEY (set_id, item_id))`:
  the merged result for every set an item reaches. Rebuilt in the same transaction as any
  change to sets, items or overrides, by the SQL function `policy_rebuild(items uuid[])` (NULL:
  all), which writes only rows that changed. The merge is `jsonb_merge_deep`; `policy::merge`
  in Rust mirrors it for tests. Writes take a transaction-level advisory lock.
- `agents.policy_set_id`: see above. `policy_set_for(pin, site, category)` resolves it; the
  `agents_policy` BEFORE trigger (on insert, and updates of site, OS, OS name, platform,
  category, manual flag or pin) sets platform, automatic category and set; `policy::reresolve`
  re-resolves in bulk.
- Views: `agent_policy` (every item reaching an agent's set whose limit includes it, with its
  merged config), `agent_patch_policy`, `agent_security_policy`. `policy_config(item, agent)`
  gives an item's config for an agent (its set's, else the item's own).

Everything that used to ask "which policies cover this agent" joins
`policy_effective e ON e.set_id = a.policy_set_id` and applies the item's limit.

### Runtime behaviour to preserve

- Alerts stay one per (policy, agent, key); `alerts.policy_id`, `log_events.policy_id`,
  `tickets.alert_policy_id` and `jobs.schedule_id` point at `policy_items(id)`.
- The polled alert checks currently run one query per policy. Now one query per (item,
  distinct effective config), binding the list of set ids that share that config
  (`a.policy_set_id = ANY($n)`), so the query count stays close to today's.
- After any policy change, for the affected agents: close open alerts whose item no longer
  applies (`resolution = 'policy'`, quietly), re-check services / security / patches, re-push
  log watchers and the sensor policy to online agents, re-run `patches::apply_policies`
  (`policy::changed`). "Affected" is: the agents an edited item reaches before and after the
  edit, the agents using a set (or one below it) whose override changed or that moved, and the
  agents whose set changed on re-resolution. Closing inapplicable alerts runs over all open
  alerts. Open alerts also take their item's new severity.
- `agent_patch_policy` stays as a view (now over `policy_effective`), so `patches.rs` changes
  little. `source` becomes the name of the set the agent uses. Its columns changed: `client_id`,
  `site_id`, `updated_by` and `updated_at` are gone (meaningless now); `set_id`, `own_window`
  and the window automatic installs use (`maint_days`, `maint_start`, `maint_minutes`,
  `maint_tz`: the policy's own window, else the site's) are new.
- The scheduler keeps `next_run_at` / `last_run_at` per schedule item in its own small table.
- Alert mutes, patch approvals, security exclusions, rule overrides and site maintenance
  windows are not policies and don't change.

## Differences from SuperOps

| SuperOps | Here | Reason |
|---|---|---|
| Six separate roots, one per category | One root, *All devices*, with OS and platform levels below | MSP-wide policies are defined once |
| "Upward inheritance": adding at a child shows the policy, disabled, at the root | Downward only | The upward rule exists to give the root an overview; the tree view and the device's effective-policy page do that |
| Overrides replace a whole policy | Per-field overrides | Sensor policy has a dozen fields; overriding one shouldn't freeze the rest |
| No revert described | Per-field and whole-item reset | |
| Association per client only | Per client and per site | Sites already carry patch windows and policies here |
| Device exception = duplicate set + new category | Pin a child set to the device | One step, and no single-device categories |
| Single-instance policy may be added anywhere, with precedence rules | Lives at the root, overridden below | No conflict cases |
| Custom categories start unassociated | A custom category must name a default set | No device is ever without a policy |

## Schema (migration `0022_policies.sql`)

New: `device_categories`, `policy_sets`, `policy_assignments`, `policy_items`,
`policy_overrides`, `policy_effective`, `policy_schedule_state`. `agents` gains `platform`,
`category_id`, `category_manual`, `policy_pin_id`, `policy_set_id`. `enrollment_tokens` gains
`category_id`. `alerts` gains `script_job_id`. Functions `jsonb_merge_deep`, `policy_rebuild`,
`policy_config`, `policy_platform`, `policy_builtin_category`, `policy_set_for`; trigger
`agents_policy`; views `agent_policy`, `agent_patch_policy`, `agent_security_policy`. The
single-instance items keep the old MSP-wide rows' ids (patch `…8000-000000000001`, security
`…0002`); remote access is `…0003`, agent `…0004`.

Data migration, in the same file (existing installs must come through unchanged in behaviour;
the `upgrade` CI job checks this):

1. Seed the built-in categories and sets and the four single-instance items with today's
   defaults; copy the MSP-wide `patch_policies` and `security_policies` rows and
   `auto_update_agents` into them.
2. Set `agents.platform` with the `is_server` rule, then `category_id`.
3. `alert_policies` → `alert` items **keeping their ids**: `os_family NULL` into *All
   devices*, otherwise into that OS's set; client, site and excluded agents become the limit.
   `schedules` → `schedule` items the same way, ids kept, run state carried over. Agents with
   `os_family = 'other'` (which now sit under Linux) are added to the exclusions of items that
   were Linux-only, so they stay uncovered.
4. For each client that has a client- or site-level patch or security policy, or
   `desktop_consent`: create client-owned child sets under each of the six leaf sets
   ("Acme · Windows servers", …) holding the overrides, and assign them for that client.
   Site-level rows get site sets as children of those, assigned for the site. Only fields
   that differ from the MSP-wide values go into the override.
5. Re-point the foreign keys, fill `policy_effective` and `agents.policy_set_id`, then drop
   `alert_policies`, `patch_policies`, `security_policies`, `schedules`,
   `clients.desktop_consent` and `company_settings.auto_update_agents`.

## API

The routes as built, with request and response shapes, are in [policies-api.md](policies-api.md).

Old CRUD routes go away (`/alert-policies*`, `/patch-policies*`, `/security/policies*`,
`/schedules` create/update/delete, `/clients/{id}/desktop`, `/agents/{id}/alert-policies`).
There are no outside API consumers yet, so no shims.

```
GET    /policy-sets                       tree, with device and item counts
POST   /policy-sets                       {name, description, parent_id, client_id?}
GET    /policy-sets/{id}                  set, ancestor chain, every item reaching it:
                                          effective config, origin set, per-field source set,
                                          this set's override if any
PUT    /policy-sets/{id}                  rename, describe, move (not built-ins)
DELETE /policy-sets/{id}
POST   /policy-sets/{id}/duplicate
GET    /policy-sets/{id}/agents           devices using it (paged)
POST   /policy-sets/{id}/items            alert or schedule item
PUT    /policy-items/{id}                 at its origin set
DELETE /policy-items/{id}
PUT    /policy-items/{id}/overrides/{set_id}     {enabled?, config (sparse)}
DELETE /policy-items/{id}/overrides/{set_id}
PUT|DELETE /policy-items/{id}/exclusions/{agent_id}

GET|POST /device-categories               PUT|DELETE /device-categories/{id}
POST   /agents/category                   {agent_ids, category_id | null = automatic}

GET    /policy-assignments?client_id=     PUT /policy-assignments   DELETE /policy-assignments/{id}

GET    /agents/{id}/policy                category, set chain, why this set (pin / site /
                                          client / default), every effective policy with sources
PUT    /agents/{id}/policy-pin            {policy_set_id | null}
POST   /agents/{id}/policy-pin/customize  create the child set and pin it
```

Kept, re-keyed to item ids: `/schedules` (read-only list across sets), `/schedules/preview`,
`/schedules/{id}` (the schedule with its last and next run; run history stays
`/jobs?schedule_id=`), `/schedules/{id}/run`.

Permissions, with no new permission set:

- MSP-wide sets, their items and overrides, categories: admin.
- A client's sets, items limited to a client, a client's assignments, pins and category moves:
  technician with access to that client.
- Anything in the `security` module also needs `security.manage`.
- Reading: anyone, filtered to the clients they can see (MSP-wide sets are visible to all).

Every mutation writes to the audit log.

## Web

- Sidebar: "Alert policies" becomes **Policies** (`/policies`, key `p`), with three tabs as in
  SuperOps: **Policy sets** (the tree, with device counts and what each set defines or
  overrides), **Device categories**, **Assignments** (pick a client; categories × sites grid).
- `/policies/sets/[id]`: breadcrumb of the chain; side sub-nav: Alerts, Scheduled scripts,
  Patching, Security, Remote access, Agent, Devices, Child sets. Every item carries one of
  *Defined here*, *Inherited from X*, *Overridden here*; inherited fields are shown with their
  value and source, become an override when edited, and have "Reset to inherited". Reuse
  `PolicyEditor.svelte`, `SensorPolicyEditor.svelte`, the patch policy form and the schedule
  form rather than rewriting them.
- Client page: a **Policies** tab with that client's assignments and its own sets.
- Agent page: a **Policy** section: category (change), the set and why, pin / customize /
  unpin, and the effective policies with sources. Replaces the alert-policy list there.
- Agents list: category column and filter; bulk "Change category".
- Patches page, Security settings, Schedules page, client desktop setting: their policy
  editors are removed and link to the policy set instead. `/schedules` stays as the list of
  scheduled scripts with last/next run.
- Enroll dialog: optional category.
- Visual and accessibility tests updated (mock API, new baselines made in Docker).

## Build order

Each step ends green (`cargo clippy --all-targets -- -D warnings`, `cargo test`, the e2e suite).

1. **Schema and core**: migration with data migration; `policy.rs` (merge, validation,
   rebuild of `policy_effective`, resolution, change fan-out); unit tests for merge,
   resolution order and validation.
2. **Consumers**: alerts, log watchers, scheduler, patches, sensor policy, remote access
   checks and auto-update read the new model; old tables and routes removed.
3. **API** as above; platform reporting in `rmm-proto` and `rmm-agent`; enrollment category.
4. **e2e**: a `policies` test (inheritance, per-field override and reset, validation
   rejection, assignment at client and site, pin, category move, limits, alert closes when a
   policy stops applying, `remote_access` 403, `run_script_id`), existing tests moved to the
   new routes, and the upgrade expectations (`RMM_E2E_EXPECT`) extended to check migrated
   policies.
5. **Web** as above, with visual tests.
6. Docs: README where it describes policies; `docs/ROADMAP.md`.

## As built

Departures from the text above, decided during the build (steps 1-4, then 5-6 below):

- **Schema details**: `agents.policy_set_id` defaults to All devices with `ON DELETE SET DEFAULT`
  and `policy_pin_id` is `ON DELETE SET NULL`, so deleting a client (which takes its sets) never
  trips a foreign key; the API itself refuses to delete a pinned or assigned set. `parent_id`
  cascades for the same reason. Depth: All devices is 0, sets may sit at depth 8 at most.
- **Category defaults** must be MSP-wide sets (categories serve every client). Built-in
  categories can't be renamed or deleted, but their default set can be changed.
- **Assignments and pins** may name an MSP-wide set or the client's own.
- **Single-instance items** are always enabled; an override can't set `enabled` for them, and
  they take no limit or exclusions.
- **Exclusions** work for schedule items too (the old schedules had none); the migration uses
  them for `other`-OS agents (above).
- **Moving a set** deletes overrides (in it and below) of items that no longer reach them.
- **Duplicate** copies the set's own items (new ids) and overrides as a sibling, not the sets
  below it; it can copy an MSP-wide set as a client's own (`client_id`).
- **Schedules** whose cron no longer parses get no next run (instead of being disabled); a
  schedule runs while it is enabled in at least one set, and each agent gets its own set's
  `args` and `timeout_secs`.
- **Remote access**: process listing and killing aren't covered by `files_enabled` (only the
  file tools are).
- **`security.manage`** is needed for the `security` module only, not for alert items of kind
  `security` (as before).
- **Settings and clients**: `/settings` loses `auto_update_agents`; `/agent-updates` reports All
  devices' `agent.auto_update` instead. `/clients` rows lose `desktop_consent`.
- **Billing**: `billing::is_server` is gone; the rule lives in `policy_platform()` and billing
  reads `agents.platform`.
- **Unit tests** cover merge, field sources, resolution order (`policy::resolve`, which explains
  the set the database resolved), validation and override limits; resolution itself happens in
  SQL and is covered by the e2e `policies` section and the `policy_migration` test.
- **`GET /policy-items/{id}`** was added in step 5: alerts carry only their item's id, and the
  web needs the item's set to open it (`/policies/items/{id}` redirects there).

Web (step 5):

- **Item editing is inline**, not in a drawer: `?section=alerts&item=<id>` (or `item=new&kind=`)
  replaces the list in the set page, so it has a URL and works the same on phones.
- **Per field**: inherited fields show the set they come from; overridden ones are tinted with a
  left rule, say *Overridden* (or *Changed*, dashed, before saving) and have **Reset**. Reset of a
  saved field is immediate (a PUT of the override without it); other unsaved edits in the same
  policy are kept. Text and icons carry the state, not only colour.
- **One form per module**, shared by defining and overriding: `components/policy/AlertForm`,
  `ScheduleForm`, `PatchForm` (was `PolicyEditor`), `SecurityForm` (was `SensorPolicyEditor`),
  `RemoteAccessForm`, `AgentForm`, wrapped by `ItemEditor`, which turns edited fields into the
  sparse override.
- **Alert maintenance windows** (mutes) moved from the old Alert policies page to the Alerts page;
  the Patches page's "Policies & windows" tab became "Maintenance windows" (site windows only).
- **Schedules**: the list stays; a schedule's page is read-only (timetable, set, runs, Run now)
  and links to the set to edit it.
- **Enroll dialog** offers custom categories only; "Automatic" covers the built-in ones.
- The old company setting and client desktop switch are replaced by a sentence linking to the
  agent and remote access policies.

## Not in this design

- Software deployment policies (roadmap block 7).
- Event triggers beyond `run_script_id` are the `automation` module: see [automations.md](automations.md).
- Importing or exporting policy sets, and policy change history beyond the audit log.
