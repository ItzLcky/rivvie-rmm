# Parity features: implementation plan

Design record, 2026-11-24. Status: plan, nothing built. Fourteen features, in seven phases. Each phase ships on its own with unit tests, e2e sections and visual baselines.

## Summary

Three shared foundations come first:

1. **Script parameters** (feature 4): typed inputs passed as environment variables, never templated into script text.
2. **A system write path into the vault**: a `vault.rs` service module extracted from `api/vault.rs`, used by BitLocker escrow, LAPS and identity resets.
3. **A check runner**: a new `rmm-checks` crate plus one `Checks`/`CheckResults` message pair, used by uptime and backup monitoring.

Decisions that apply throughout:

- **Secrets never ride in script jobs.** LAPS, recovery keys and AD password resets use dedicated protocol messages over the agent socket.
- **New monitoring is alert kinds**, so severity, channels, tickets, mutes, automations and health work unchanged. Health is driven by open alerts through the `0026` triggers.
- **"Per-MSP" branding is instance settings**; a narrow per-client override covers what a client's users see.
- **`paging.rs` is keyset pagination.** On-call is new and lives in `oncall.rs`.
- **Build migrations that add a policy module one at a time.** Each must re-declare `policy_items_module_check` (and `policy_items_limit_modules` for multi-instance modules) with the full list from `0035` plus its own.

### Order

| Phase | Features | Why here |
|---|---|---|
| A. Foundations | 4 script parameters; vault system writes | Small, unblock B and F |
| B. Device security | 1 disk encryption and escrow; 2 LAPS | Highest value per effort, both use the vault path |
| C. Monitoring reach | 5 uptime (check runner); 11 backup; 6 Wake-on-LAN | Share the runner and the site's designated agent |
| D. Presentation and comms | 9 white-label; 7 scheduled reports; 10 on-call; 14 PWA and push | Branding feeds reports, emails, PWA manifest; push is an on-call method |
| E. Vulnerabilities | 3 CVE reporting | Large and standalone |
| F. Identity | 12 AD and Entra, ticket templates; 13 Intune read-only | Shares the per-client Entra connection |
| G. End-user tray | 8 tray app | Needs branding; most manual Windows testing |

## Migration numbering

`0025` stays unused. One migration per shippable step:

| No. | File | Contents |
|---|---|---|
| 0036 | `script_params.sql` | `scripts.params`, `jobs.params`, `jobs.env_sealed` |
| 0037 | `vault_managed.sql` | `vault_items.managed_kind`, `agent_id`, `managed_ref`, `managed_state` |
| 0038 | `disk_encryption.sql` | `disk_volumes`, agent columns, `disk_encryption` module and seed item |
| 0039 | `local_admin.sql` | `local_admin_state`, `local_admin` module and seed item |
| 0040 | `uptime.sql` | `uptime_monitors`, `uptime_results`, `uptime_hourly`, `alerts.monitor_id`, health function |
| 0041 | `alerts_without_agent.sql` | `alerts.client_id NOT NULL` (backfilled), `agent_id` nullable (step C1b) |
| 0042 | `backups.sql` | `backup_jobs` |
| 0043 | `wol.sql` | `agents.wol_sent_at` |
| 0044 | `branding.sql` | `branding` |
| 0045 | `report_schedules.sql` | `report_schedules`, `report_runs` |
| 0046 | `oncall.sql` | channel kinds, SMS settings, schedules, escalation, pages, `users.phone` |
| 0047 | `push.sql` | `push_keys`, `push_subscriptions`, `user_notification_prefs` |
| 0048 | `vulnerabilities.sql` | `vulns`, `vuln_ranges`, `vuln_products`, `vuln_findings`, `vuln_feeds`, `vuln_acceptances` |
| 0049 | `identity.sql` | `identity_sources`, `identity_users`, `identity_groups`, `identity_group_members` |
| 0050 | `ticket_templates.sql` | `ticket_templates`, `ticket_checklist_items`, `tickets.identity_user_id` |
| 0051 | `mdm.sql` | `mdm_devices` |
| 0052 | `tray.sql` | `tray` module and seed item, `tickets.source_ref`, `company_settings.tray_board_id` |

Every new `*_sealed boolean` column needs a `rotate::TABLES` entry: the unit test `every_sealed_flag_in_the_migrations_is_listed` fails otherwise. Affected: `0046` (SMS token), `0047` (VAPID key), `0049` (Entra secret). `jobs.env_sealed` is a `bytea` that is always sealed, so it needs an entry with `flag: None` and `aad_prefix: Some("job-env:")`.

Also extend, per feature: the message-kind index at the bottom of `agent_ws.rs`, `policy::ALERT_KINDS`, `Perm::ALL`, `Permission` in `web/src/lib/session.svelte.ts`, `api::public::OPS` where stated, `tests/upgrade.rs` seeds, and `web/tests/visual/mock.ts`.

---

## Phase A: foundations

### A1. Script parameters and variables (feature 4)

**Decision: environment variables.** A parameter value reaches the script as `RMM_PARAM_<NAME>`, set on the child process. The script body is never rewritten. Reasons:

- Templating a value into script text is command injection (a hostname or custom field containing `$(…)` or `"; …`).
- `jobs.body` and `jobs.args` are stored in the clear and shown in the UI.
- `cmd.exe /C path args` re-parses its arguments, so even argv is unsafe for one interpreter. Environment variables are safe for all five.

`{{…}}` placeholders are allowed only inside parameter *values* (run dialog, schedule and automation items). The server expands them per device before the job is created; the result is still just an environment value. `args` stay literal.

**Scope in:** typed parameters on saved scripts (`text`, `number`, `bool`, `select`, `secret`); prompts at run time; values in `schedule` and `automation` items, overridable in descendant sets like `args`; built-ins.

**Scope out:** parameters on ad-hoc scripts; output redaction (document "don't echo secrets"); file-upload parameters.

**Built-ins** (always set):

- `RMM_AGENT_ID`, `RMM_AGENT_HOSTNAME`, `RMM_AGENT_OS`, `RMM_AGENT_PLATFORM`
- `RMM_CLIENT_ID`, `RMM_CLIENT_NAME`, `RMM_SITE_ID`, `RMM_SITE_NAME`
- `RMM_JOB_ID`

Placeholders: `{{agent.hostname}}`, `{{agent.id}}`, `{{agent.os}}`, `{{client.name}}`, `{{site.name}}`, `{{field.<name>}}`. A custom field value is resolved agent, then site, then client. Fields are passed only when referenced, because a hundred 2,000-character fields would exceed the Windows environment block. An unknown placeholder is a 400 at save time.

**Data model (0036):**

- `scripts.params jsonb NOT NULL DEFAULT '[]'`: `[{name, label, type, required, default, choices, description}]`. Name is `[a-z][a-z0-9_]{0,39}`; at most 30.
- `jobs.params jsonb NOT NULL DEFAULT '{}'`: what was passed, secrets as `"•••"`.
- `jobs.env_sealed bytea`: the secret values of a queued job, sealed with `RMM_DATA_KEY` (AAD `job-env:<job id>`), set to NULL when the job leaves `queued`/`sent`.

Secret parameters need `RMM_DATA_KEY` (409 otherwise, as the vault does).

**Secrets in policy items** are never stored in `policy_items.config`. The value must be `vault:<uuid>`, resolved at launch against the device's client. The item must therefore be limited to that client; this is validated at write time.

**Proto:**

- `ScriptJob.env: Vec<(String, String)>` with `#[serde(default)]`.
- Capability `script_env` in `Auth.capabilities`.
- A job with parameters for an agent without the capability ends `error: "agent too old for script parameters"` instead of running without them.

**Agent** (`jobs.rs`): `Command::envs(job.env)` in `execute`. Names are re-validated (`RMM_[A-Z0-9_]+`), each value is capped at 8 KiB and the total at 24 KiB. Nothing is written to the job store on disk except the fact that env existed.

**Server:**

- New `src/params.rs`: `Spec`, `validate_specs`, `coerce` (reuse the rules of `fields::coerce`), `expand(value, ctx)`, `env_for(script, values, agent_ctx)`.
- `api/scripts.rs`: `params` in `ScriptIn` and `Script`.
- `api/jobs.rs::create`: `params: Map<String, Value>` in `NewJob`. Env is built per agent, so `deliver_many` needs a per-job `ScriptJob` whenever expansion is used.
- `policy.rs`: `params: BTreeMap<String, String>` on `ScheduleConfig` and `AutomationConfig`, in the override allow-list of `clean_override`, validated against the script in `validate_effective`.
- `scheduler::run_schedule`, `automation::launch` and `alerts::run_alert_script` call `params::env_for`.
- Changing a script's parameters re-validates every item that uses it and answers 409 naming the item.

**API:** existing routes gain fields. `createJob`, `getScript` and `listScripts` schemas in `api/public.rs` gain `params`. An API key may pass secret values but not `vault:` references (the vault is not in the public API).

**RBAC and audit:**

- Unchanged roles.
- `job.create` audit lists parameter names and non-secret values.
- Using a vault item as a value needs `vault.read` and writes `vault.use` (item, job).

**UI:**

- `scripts/[id]`: a Parameters editor (`components/scripts/ParamsEditor.svelte`).
- `RunScript.svelte`: typed inputs through a shared `ParamInputs.svelte`; a secret is a password input or a "From vault" picker (`VaultPicker`).
- `ScheduleForm` and `AutomationForm`: the same inputs plus an "Insert variable" menu.
- `jobs/[id]`: a Parameters panel.

**Tests:**

- Unit: spec validation, coercion, expansion, env-name mapping, "the body is never touched".
- e2e `script_params`:
  - a bash script echoes its env;
  - a value of `$(touch X); "` arrives verbatim and X does not exist;
  - a secret is absent from `jobs` and `audit_log`;
  - a queued job to an offline agent delivers the secret after reconnect, then `env_sealed` is NULL;
  - a schedule override changes one parameter;
  - `{{field.x}}` expands per device;
  - an agent without the capability gets `error`.
- Windows e2e: PowerShell `$env:RMM_PARAM_X` and cmd `%RMM_PARAM_X%`.
- Visual: script page with parameters, run dialog, schedule form.

**Risks:** environment variables are readable by same-user processes and child processes. Scripts run as root/SYSTEM, so this is acceptable; document it.

### A2. Vault system write path

**Decision:** move `client_key`, `seal` and `open` from `api/vault.rs` to a new `src/vault.rs` and add:

```
vault::put_managed(st, client_id, Managed { kind, agent_id, reference, name, username, url, notes }, password, source) -> ApiResult<Uuid>
```

It upserts on `(client_id, managed_kind, managed_ref)`, pushes the replaced password to `vault_item_history` (last 10 are kept) and audits `vault.system_write` with fields but never values.

**Data model (0037)** on `vault_items`:

- `managed_kind text CHECK (… IN ('disk_recovery', 'local_admin', 'identity'))`
- `agent_id uuid REFERENCES agents ON DELETE SET NULL`. Deleting a device must not delete its recovery key; the hostname is kept in `name`.
- `managed_ref text`, `managed_state text`
- a partial unique index on `(client_id, managed_kind, managed_ref) WHERE managed_kind IS NOT NULL`

**Rules:**

- Without `RMM_DATA_KEY` the callers report "needs RMM_DATA_KEY" and do nothing. LAPS never rotates a password it cannot store.
- A user cannot edit a managed item's password or username (`PUT /vault/{id}` answers 409). Delete needs `vault.manage`. Reveal is as today (2FA, rate limit, `vault.reveal`).
- `api/vault.rs` lists gain `managed_kind`, `agent_id`, `managed_state` and a `?kind=` filter.

**UI:** a "Managed" badge and filter in `ClientVault.svelte`; `CredentialCard` gets a read-only variant.

**Tests:** e2e in the `docs_and_vault` section: upsert twice makes one item with one history row; the agent is deleted and the item remains; a user edit is refused; `rotate-data-key` still opens it.

---

## Phase B: device security

### B1. Disk encryption status and recovery-key escrow (feature 1)

**Scope in:**

- Status per fixed volume on Windows (BitLocker), macOS (FileVault) and Linux (LUKS/dm-crypt).
- Escrow of BitLocker recovery passwords into the client's vault.
- Optionally adding a recovery-password protector where none exists.
- A manual "rotate recovery key" action.
- An alert kind.

**Scope out:**

- *Turning encryption on.* It needs TPM readiness, reboots and user communication; offer a library script later.
- FileVault key escrow: the key cannot be read after the fact, and rotating it needs user credentials or an MDM bootstrap token.
- LUKS escrow: adding a key slot needs an existing passphrase.
- Removable drives (BitLocker To Go).

**Data model (0038):**

- `disk_volumes`, primary key `(agent_id, volume_id)`:
  - `mount`, `device`, `kind` (`bitlocker`/`filevault`/`luks`/`none`), `role` (`os`/`data`)
  - `status` (`encrypted`/`encrypting`/`decrypting`/`unencrypted`/`suspended`/`unknown`), `percent`, `method`
  - `protectors text[]`, `protection_on`, `locked`
  - `recovery_protector_id`, `escrowed_protector_id`, `escrowed_at`
  - `vault_item_id REFERENCES vault_items ON DELETE SET NULL`, `updated_at`
- `agents.diskenc_at`, `agents.diskenc_error`, `agents.tpm jsonb`.
- Policy module `disk_encryption`, single-instance, seed item `00000000-0000-4000-8000-000000000005` in All devices: `{escrow_recovery_keys: true, add_recovery_protector: false}`.

**Agent** (`src/diskenc/{mod,bitlocker,filevault,luks,fake}.rs`): reports on connect, every 6 hours and on request.

- **Windows:** one embedded PowerShell script (the pattern `security/defender.rs` uses) over CIM `Win32_EncryptableVolume` in `root/CIMV2/Security/MicrosoftVolumeEncryption`, calling `GetConversionStatus`, `GetProtectionStatus`, `GetKeyProtectors`, `GetKeyProtectorNumericalPassword`. This works without the BitLocker PowerShell module. Fallback: parse `manage-bde -status`. TPM comes from `Win32_Tpm`. "Class not found" (a Server without the feature) is reported as `unencrypted`, not as an error.
- **macOS:** `fdesetup status` and `diskutil apfs list -plist`.
- **Linux:** `lsblk -J -o NAME,TYPE,FSTYPE,MOUNTPOINT,UUID,PKNAME`. A mounted filesystem whose ancestor is `crypt` or `crypto_LUKS` is encrypted. Only `/`, `/home` and other local non-removable mounts are listed.
- **Debug builds:** `RMM_DISKENC_FAKE=<file>`.

**Recovery keys are pulled, not pushed.** The status report carries protector ids only. The server asks for one key when a volume's recovery protector id differs from the escrowed one and the policy says escrow.

**Proto** (`rmm-proto/src/diskenc.rs`, capability `diskenc`):

- `AgentMsg::DiskEncryption(Report { volumes, tpm, error })`
- `ServerMsg::DiskEncryptionRefresh`
- `ServerMsg::DiskRecoveryRequest { request_id, volume_id, protector_id }` → `AgentMsg::DiskRecoveryKey { request_id, volume_id, protector_id, key: Option<String>, error }`
- `ServerMsg::DiskProtector { request_id, volume_id, op: AddRecovery | RotateRecovery }` → `AgentMsg::DiskProtectorResult { request_id, ok, message }`

**Server** (`src/diskenc.rs`):

- `ingest_report` upserts volumes and deletes ones that disappeared.
- It then requests missing keys and calls `vault::put_managed(kind = disk_recovery, reference = "<agent>:<volume>", name = "BitLocker recovery: HOST C:", username = <protector id>)`.
- It accepts a key only from the agent that was asked, for a pending `request_id`.
- `alerts::diskenc_reported` follows the shape of `security_reported`.

**API** (`api/diskenc.rs`):

- `GET /agents/{id}/disk-encryption`
- `POST /agents/{id}/disk-encryption/refresh` (technician)
- `POST /agents/{id}/disk-encryption/{volume}/rotate-key` (`security.respond`)
- `GET /disk-encryption?client_id&status&escrowed` (paged fleet list)

Public API: the two GETs under group `security` (`listDiskEncryption`, `getAgentDiskEncryption`). Keys are reachable only through the vault, which is not public.

**RBAC and audit:**

- Status: anyone who sees the agent.
- Key: `vault.read` plus 2FA (existing reveal).
- Rotate: `security.respond`.
- Events: `diskenc.escrow` (volume, protector id), `diskenc.rotate`, `vault.system_write`.

**Alert kind `disk_encryption`:** `{volumes: "os" | "all_fixed", require_escrow: true, grace_hours: 24}`. One alert per volume (key `vol:<id>`). Findings: `unencrypted`, `suspended` for longer than the grace period, `not_escrowed` (Windows only). `encrypting` is not a finding. It is rechecked on report, `recheck_item` and `recheck_agent`.

**UI:**

- A "Disk encryption" card on the agent Inventory tab (`components/agent/AgentDiskEncryption.svelte`) with a "Recovery key" button opening `CredentialCard`.
- An Encryption column and `?encryption=` filter on `/agents` (add the key to the saved-view whitelist).
- A Security page tab "Disk encryption" (fleet list).
- `components/policy/DiskEncryptionForm.svelte` and the `AlertForm` kind.
- A QBR block "Disk encryption coverage".

**Tests:**

- Unit: parsers against recorded CIM JSON, `manage-bde`, `fdesetup` and `lsblk` output (`tests/fixtures/diskenc/`); the findings function.
- e2e `disk_encryption` with the fake:
  - an unencrypted volume opens an alert and health changes;
  - the fake flips to encrypted with a protector, the key is requested, a vault item exists and reveal returns it;
  - a new protector id updates the item and adds a history row;
  - a key from a different agent is ignored;
  - without `RMM_DATA_KEY` nothing is requested.
- Windows e2e: a report arrives and lists `C:`. The runner has no BitLocker, so escrow there is unproven.

**Risks:** recovery passwords cross the agent socket (same trust as SNMP credentials today). Group Policy may forbid numerical-password protectors, in which case `add_recovery_protector` fails with a message. Real BitLocker goes into `windows-testing.md`.

### B2. Local admin password rotation (feature 2)

**Scope in:** one managed local account per device on Windows and Linux, optionally created; rotation on schedule, after a reveal, and on demand; the password in the client's vault.

**Scope out:**

- macOS: `sysadminctl` and `dscl` take the password on argv, and SecureToken and keychain break.
- Domain controllers: local accounts are domain accounts there, so the agent reports `unsupported`.
- Several accounts per device.

**Decision: a dedicated message, not a script.** The server generates the password and **stores it before the agent sets it**:

1. `vault::put_managed(kind = local_admin, managed_state = 'pending')`. The old password moves to history.
2. `ServerMsg::LocalAdminSet`.
3. On `ok`, the state becomes `current`.

A lost reply or a failure leaves the item `pending` with the previous password in history, so nobody is locked out. A retry reuses the pending password instead of generating a new one.

**Data model (0039):**

- `local_admin_state`: `agent_id` (PK), `account`, `vault_item_id`, `status` (`ok`/`pending`/`failed`/`unsupported`/`conflict`), `rotated_at`, `next_rotate_at`, `rotate_reason`, `attempts`, `last_error`.
- Policy module `local_admin`, single-instance, seed item `…000000000006`: `{enabled: false, account: "rmmadmin", create: true, rotate_days: 30, length: 20, rotate_after_reveal_hours: 24}`. Enable it by overriding in, say, Windows workstations.

**Proto** (capability `local_admin`):

- `ServerMsg::LocalAdminSet { request_id, account, password, create }` → `AgentMsg::LocalAdminResult { request_id, ok, created, status, message }`.
- Never queued for offline agents; the server retries on connect and every minute.

**Agent** (`src/localadmin.rs`):

- **Windows:** `NetUserSetInfo` level 1003 and `NetUserAdd`, plus `NetLocalGroupAddMembers` by SID `S-1-5-32-544` (group names are localised). This needs the `windows` crate feature `Win32_NetworkManagement_NetManagement`. Never `net user <name> <password>`: command lines show in process lists and EDR logs. Refuse when `ProductType` is `LanmanNT`. Report `conflict` when Windows LAPS manages the same account (`HKLM\SOFTWARE\Microsoft\Policies\LAPS` or `…\Windows\CurrentVersion\Policies\LAPS`, `BackupDirectory` not 0).
- **Linux:** `chpasswd` with `user:password` on stdin. Create with `useradd -m` and add to `sudo` or `wheel`, whichever exists.
- The password is never logged or persisted. Debug: `RMM_LOCALADMIN_FAKE=<file>` records what was set.

**Server** (`src/localadmin.rs`):

- `generate(length)`: CSPRNG over upper, lower, digits and symbols, excluding ambiguous characters, with at least one of each class.
- `tick()` (every minute, and on connect): for agents whose effective policy is enabled and `next_rotate_at <= now` and that are online.
- `revealed(item)`: called from `api/vault.rs::reveal`; sets `next_rotate_at = now + rotate_after_reveal_hours`.
- Disabling the policy stops rotation and leaves the account and item in place; the UI says so.

**API:** `GET /agents/{id}/local-admin`, `POST /agents/{id}/local-admin/rotate` (technician plus `vault.manage`). Not in the public API.

**Audit:** `local_admin.rotate` (trigger: schedule, reveal, manual, first), `local_admin.result`.

**Alert kind `local_admin`:** `{overdue_days: 7}`. It opens when rotation is `failed`, `conflict`, or overdue.

**UI:**

- `LocalAdminForm.svelte` in the policy set.
- A card on the agent overview (account, last rotated, next, status, "Show password" through `CredentialCard`, "Rotate now").
- Managed items in the client's Passwords tab.

**Tests:**

- Unit: the generator, the state machine (pending → ok, pending → failed → retry with the same password), the reveal trigger.
- e2e `local_admin` with the fake: enable by override, an item appears, reveal equals what the fake recorded, reveal schedules a rotation (shortened with `RMM_LOCALADMIN_TICK_SECS`), a failure keeps the previous password in history and opens the alert.
- Windows e2e (the runner is an administrator): the real path. Create `rmm-e2e-admin`, rotate, verify with `LogonUserW` from PowerShell, delete.

**Risks:** local password policy may reject the password (the default satisfies complexity; the message is surfaced). Linux hosts without `chpasswd` report `unsupported`.

---

## Phase C: monitoring reach

### C0. Check runner (shared by C1 and C2)

**New crate `crates/rmm-checks`**, a small library with no HTTP framework:

- `ping`: Linux datagram ICMP moved from `rmm-agent/src/net/icmp.rs`; Windows `IcmpSendEcho` (feature `Win32_NetworkManagement_IpHelper`); macOS datagram ICMP.
- `tcp`: connect.
- `http`: a minimal HTTP/1.1 GET/HEAD over `tokio-rustls`, built from what `rmm-agent/src/fetch.rs` already does. Reads at most 256 KiB, follows at most 5 redirects.
- `tls`: handshake with a verifier that records and never rejects, then read `notAfter`, subject, issuer and SANs with the BER reader from `rmm-snmp` (`ber.rs`). No `x509-parser` dependency.
- `dns`: A, AAAA, CNAME, MX, TXT, extending `rmm-agent/src/net/dns.rs`, which moves here.

The agent's `net/` module re-uses the crate; the server links it for server-run checks.

**Proto** (`rmm-proto/src/checks.rs`, capability `checks`):

- `ServerMsg::Checks { checks: Vec<CheckSpec> }`: the full set, replacing the previous one; pushed on connect and on change, like `Watchers`.
- `CheckSpec { id, interval_secs (30–86400), timeout_secs, kind }`, where `kind` is one of `Ping`, `Tcp`, `Http`, `Tls`, `Dns`, `Backup`.
- `AgentMsg::CheckResults { results: Vec<CheckResult { check_id, at, ok, latency_ms, value, message, data }> }`, batched every 30 seconds and sent immediately on a state change.

The agent keeps no state across restarts. At most 200 checks, 16 in flight.

### C1. Uptime checks (feature 5)

**Scope in:**

- Ping, TCP port, HTTP(S) status and keyword, TLS certificate expiry, DNS.
- Run from an agent (step C1a) or from the server (step C1b).
- Availability and latency history.

**Scope out:** multi-step or scripted transactions, browser checks, multi-region consensus, public status pages.

**Data model (0040):**

- `uptime_monitors`:
  - `id`, `client_id`, `site_id`, `name`, `kind`, `config jsonb`
  - `runner` (`agent`/`server`), `agent_id` (NULL means the site's designated agent, `site_network.agent_id`)
  - `interval_secs`, `timeout_secs`, `enabled`
  - `state` (`up`/`down`/`unknown`), `state_since`, `fail_count`, `last_at`, `last_ms`, `last_message`, `cert_not_after`
- `uptime_results (monitor_id, ts, ok, ms, message)`, kept `RMM_METRICS_RAW_DAYS`.
- `uptime_hourly (monitor_id, hour, checks, failures, avg_ms, max_ms)`, written by the housekeeping loop like `netmon::rollup`.
- `alerts.monitor_id uuid REFERENCES uptime_monitors ON DELETE CASCADE`.
- `refresh_agent_alerts` replaced so that monitor alerts, like device alerts in `0033`, don't count against the runner agent's health.

**Alert kind `uptime`**, on the runner agent's policy set (the `net_down` precedent):

- Params: `{failures: 2, kinds: [], cert_days: 14, latency_ms: null}`.
- Keys: `mon:<id>`, `mon:<id>:cert`, `mon:<id>:latency`.
- A monitor whose runner agent is offline goes `unknown`, not `down`.
- Not added to the automations' `ALERT_KINDS`: a script on the runner is the wrong machine (same rule as network alerts).

**Step C1b, server-run (0041).** `alerts.agent_id NOT NULL` is assumed by about 36 queries in `alerts.rs`, `notify.rs`, `tickets.rs`, `webhooks.rs`, `policy.rs`, `api/{alerts,tickets,channels,reports,policies}.rs`, plus `hub::Event::Alert`, `siem.rs` and the web alert types. The step:

- Add `alerts.client_id NOT NULL`, backfilled from agent → site.
- Make `agent_id` nullable; switch those joins to `LEFT JOIN agents` and read the client from the alert.
- Server-run monitors are evaluated against `uptime` items defined in **All devices** whose limit covers the monitor's client and site.
- The server runner is `uptime::run` in `main.rs`.

Ship C1a first. C1b is its own PR with the full e2e run. It also unlocks later agentless alerts (Intune compliance, failed report deliveries).

**SSRF rules:**

- A server-run check refuses loopback, private, link-local and metadata addresses *after* resolution, and again on every redirect, unless `RMM_UPTIME_ALLOW_PRIVATE=1`.
- Agent-run checks may reach private space, which is their purpose.
- Neither returns response bodies: only status, latency, "keyword found" and certificate fields.
- URLs with embedded credentials are refused.

**Server:** `src/uptime.rs` (`checks_for(agent)`, `ingest`, `evaluate`, `rollup`, `prune`, `run`). `policy::changed` and the monitor CRUD re-push `Checks`.

**API** (`api/uptime.rs`):

- `GET|POST /uptime/monitors`
- `GET|PUT|DELETE /uptime/monitors/{id}`
- `POST /uptime/monitors/{id}/check`
- `GET /uptime/monitors/{id}/results?from&to`
- `GET /uptime/summary`

Reads: anyone scoped to the client. Changes: technician. Audit `uptime.*`. Public API: `listUptimeMonitors`, `getUptimeMonitor`, `getUptimeResults` under group `network`.

**UI:**

- `/uptime` (sidebar, Monitoring) and `/uptime/[id]`: state, a 90-day availability bar, latency chart (`Chart.svelte`), certificate details.
- A create/edit drawer with the runner picker.
- The `AlertForm` kind.
- A QBR block "Availability".

**Tests:**

- Unit: an HTTP status-line and chunked parser, the keyword match, `notAfter` extraction from a DER fixture, the consecutive-failure logic, SSRF address classes.
- e2e `uptime`:
  - local HTTP and TLS listeners with certificates generated by an `rcgen` dev-dependency (valid, expiring in 5 days, expired);
  - one monitor of each kind against them; stop the listener and the alert opens after 2 failures; restart and it resolves;
  - a certificate alert;
  - the runner agent goes offline and the monitor is `unknown` with no alert;
  - another client's technician gets 404.
- C1b adds a server-run monitor and the refused `127.0.0.1` target.
- Visual: list, detail, form.

### C2. Backup monitoring (feature 11)

**Scope in (monitoring only):** read the last result and time of backup jobs on the endpoint.

**Providers:**

| Provider | Source |
|---|---|
| `wsb` (Windows Server Backup) | `Get-WBSummary` as JSON; fallback to event log `Microsoft-Windows-Backup` (4 = success, others = failure) |
| `veeam` (Backup & Replication, and Agent for Windows) | event logs `Veeam Backup` and `Veeam Agent`, event 190 (job finished, with result), read through the `wevtutil` path `logwatch.rs` uses; no Veeam PowerShell module (slow to load, version-bound) |
| `restic` | `restic snapshots --latest 1 --json` with an **env file already on the machine** (`{env_file: "/etc/restic/env"}`); no secret comes from the server |
| `borg` | `borg list --last 1 --json`, same env-file rule |
| `timemachine` | `tmutil latestbackup` and `com.apple.TimeMachine` preferences |
| `file_age` | the newest file matching a glob under a path; covers products that drop files (SQL dumps, Synology targets) |
| `auto` | probes `wsb` and `veeam` by service presence (`wbengine`, `VeeamBackupSvc`, `VeeamEndpointBackupSvc`) |

**Scope out:**

- Vendor cloud APIs (Veeam Service Provider Console, Datto, Acronis, MSP360, Synology Active Backup, Microsoft 365 backup).
- Starting or configuring backups; restore tests.

**Data model (0042):** `backup_jobs`, primary key `(agent_id, provider, job)`: `last_run_at`, `last_success_at`, `last_result` (`success`/`warning`/`failed`/`running`/`unknown`), `message`, `size_bytes`, `updated_at`.

**Alert kind `backup`**, on the device's own policy set; the check spec is derived from the item for each agent it reaches, as `watchers_for` derives log watchers:

- Params: `{providers: ["auto"], sources: [{provider, env_file, repo, path, glob}], jobs: ["*"], max_age_hours: 26, warning_is_failure: false, require: false}`.
- Findings: `failed`, `stale` (no success within `max_age_hours`), and `none_found` when `require` is set (for server sets).
- Key: `backup:<provider>:<job>`.
- Added to `ALERT_KINDS` so an automation can react.

**Agent** (`src/checks/backup/{wsb,veeam,restic,borg,timemachine,file_age}.rs`):

- `CheckKind::Backup` returns `data` as a JSON list of jobs; default interval one hour.
- Paths and env files are validated: absolute, no `..`, root-owned and not world-writable on Unix.
- Tools are executed without a shell.
- Debug: `RMM_BACKUP_FAKE=<file>`.

**API:** `GET /backups?client_id&result` (paged), `GET /agents/{id}/backups`. Public API: both, group `agents`.

**UI:** `/backups` (fleet table: device, product, job, last success, result); a Backups card on the agent overview; the `AlertForm` kind with a sources editor; a QBR block "Backup success".

**Tests:**

- Unit: parsers against recorded `Get-WBSummary`, Veeam event XML, restic and borg JSON, `tmutil`.
- e2e `backups`: the fake for alert logic (fresh success, failure, stale, recovery). A real restic repository when `restic` is on PATH (install it in the CI e2e job; skip locally when absent).
- Windows e2e (stretch): `Install-WindowsFeature Windows-Server-Backup` and assert an empty `wsb` summary parses.

### C3. Wake-on-LAN (feature 6)

**Scope in:** wake one device or many through an online agent on the same site; optional wake before a patch window.

**Scope out:**

- Waking discovered (unmanaged) devices.
- Configuring BIOS or NIC wake settings (a library script).
- Wake before software-policy windows.

**Proto** (in `rmm-proto/src/net.rs`, capability `wol`):

- `ServerMsg::WakeOnLan { request_id, targets: Vec<WolTarget { mac, last_ip }> }` → `AgentMsg::WakeOnLanResult { request_id, sent, error }`.

**Agent** (`src/net/wol.rs`): the magic packet (6 × `FF`, then the MAC 16 times) to UDP ports 9 and 7, three times, sent to `255.255.255.255` and to the directed broadcast of every interface (the one whose subnet holds `last_ip` first). Debug: `RMM_WOL_FAKE=<addr:port>` redirects the packets.

**Server** (`src/wol.rs`): `wake(agent_ids, by)`.

- Target MACs come from `agents.inventory.network[].mac` (skip loopback, all-zero and virtual prefixes).
- The sender is the site's designated agent when online, else any online agent of the site with the capability, preferring one that shares a subnet with the target's last addresses.
- Per-agent outcome: `sent`, `no_mac`, `no_sender`, `online`.

**Patch window:** `PatchConfig.wake_before_minutes: Option<i32>` (0–60, `#[serde(default)]`, overridable; no migration for the config). In `patches::scheduler_tick`: offline agents with eligible approved patches whose effective window opens within that many minutes, and whose `wol_sent_at` (0043) is older than 12 hours, are woken.

**API:** `POST /agents/{id}/wake`, `POST /agents/wake {agent_ids}` (up to 5,000; technician). Audit `agent.wake`. Public API: `wakeAgent` and `wakeAgents`, group `agents`, write.

**UI:** "Wake" on an offline agent's header; a bulk action on `/agents`; a `PatchForm` field.

**Tests:**

- Unit: the packet bytes, the MAC filter, the sender choice.
- e2e (in the `network` section): the test binds a UDP socket and points `RMM_WOL_FAKE` at it; waking the stopped agent B through agent A delivers a packet carrying B's MAC; the bulk call reports `no_sender` for a site with nobody online; the patch-window wake fires once.
- Real wake-ups need hardware: manual.

---

## Phase D: presentation and comms

### D1. White-labelling (feature 9)

**Decision:** the product is self-hosted per MSP, so instance branding is one row. A per-client row overrides what that client's people see (portal after sign-in, tray app, emails to its contacts).

**Scope in:** product name, logos (light and dark), square icon, accent colour, support contact card (phone, email, URL, hours), email from-name and footer, PDF header logo, display names of installers.

**Scope out:**

- Per-client console theming.
- Custom CSS; SVG uploads (sanitising risk).
- Per-client portal branding before sign-in.
- **Renaming the binary, service id, install paths or package id** (`rmm-agent`, `/etc/rmm-agent`): self-update, MSI upgrade codes, scripts and docs depend on them.

**Data model (0044):** `branding` with `client_id uuid UNIQUE NULLS NOT DISTINCT` (NULL is the instance): `product_name`, `logo_light`, `logo_dark`, `icon` (storage keys), `accent` (`#rrggbb`), `support_email`, `support_phone`, `support_url`, `support_hours`, `email_from_name`, `email_footer`, `updated_by`, `updated_at`.

**Server** (`src/branding.rs`):

- `resolve(client_id) -> Branding` (client over instance over built-in), cached in `AppState` like `Company`.
- Accent validation: contrast at least 4.5:1 against the on-accent colour it picks, in both themes.
- Uploads: PNG or JPEG only, at most 512 KiB, decoded with a new `png` dependency to check dimensions and to produce the PDF and `.ico` forms.

**Surfaces:**

- **Console and portal:** `settings::public` and `portal::public_info` return branding. `web/src/routes/+layout.svelte` sets the accent CSS variables (the tokens in `layout.css` were built for this). `static/theme.js` applies the cached value before paint. Product name in the rail, title and login.
- **Email:** from-name and a text footer in `email.rs` builders (emails are plain text today).
- **PDF:** `pdf.rs` gains an image XObject (FlateDecode RGB plus SMask) for the header of `report` and `invoice`.
- **Packages:**
  - `api/msi.rs`: `ProductName` and the ARP display name.
  - `api/packages.rs`: download filename `<slug>-agent-<ver>.msi|deb|rpm`, deb `Description`, rpm `Summary`.
  - Service *display* name: passed in `enroll.toml` as `product_name` and used by `service.rs` at install.
- **Agent:** consent prompt titles; the tray (phase G).

**API:**

- `GET|PUT /settings/branding` (admin)
- `POST|DELETE /settings/branding/{logo_light|logo_dark|icon}` (multipart)
- `GET|PUT|DELETE /clients/{id}/branding` (admin)
- `GET /api/branding/{variant}` (public, `ETag`, optional `?client=` only for a signed-in contact)

Audit `branding.update`. Not in the public API.

**UI:** Settings → Branding (live preview of rail, login, email, contact card); a Branding section on the client page.

**Tests:**

- Unit: contrast, hex parsing, slug, image checks.
- e2e `branding`: set it, then public settings and the portal return it; `smtp_sink` mail has the from-name and footer; the MSI's `ProductName` property reads back; the QBR PDF contains an `/XObject`; a client override reaches that client's contact only.
- Visual: login, rail and portal with a branded fixture in `mock.ts`, both themes.

**Risk:** the licence is AGPL-3.0-or-later, and §13 requires offering the source to network users. Keep a "Licence and source" link in the console's About and the portal footer whatever the branding. Raise with the owner before promising "no trace of the product".

### D2. Scheduled and emailed reports (feature 7)

**Scope in:** the four existing reports (service desk, utilisation, profitability, QBR) as PDFs on a cron timetable, emailed to users and client contacts; history and "send now".

**Scope out:** a report builder; CSV/XLSX; new report types beyond the QBR blocks other features add; portal download page.

**Data model (0045):**

- `report_schedules`: `id`, `name`, `report`, `client_id`, `params jsonb` (`{range: last_week | last_month | last_quarter | last_30_days}`), `cron`, `timezone`, `user_ids uuid[]`, `contact_ids uuid[]`, `extra_emails text[]`, `subject`, `message`, `enabled`, `owner_id`, `next_run_at`, `last_run_at`, `last_status`, `last_error`.
- `report_runs`: `id`, `schedule_id`, `started_at`, `status`, `storage_key`, `bytes`, `recipients jsonb`, `error`.

**Rules:**

- A schedule runs **with its owner's access evaluated at run time**. If the owner lost `billing.read` or the client, the run fails with that reason instead of leaking figures.
- Contacts may receive only `qbr` and client-scoped `service_desk` for *their* client; `profitability` and `utilisation` never go to contacts. Checked at save and again at run.
- `extra_emails` is admin-only.

**Server:**

- Refactor `api/reports.rs` so each handler is `build_*(st, scope, range) -> Data` plus a JSON view. Add `blocks_*` for `pdf::report` (the QBR already builds blocks).
- New `src/reports.rs`: `run()` loop claiming due rows `FOR UPDATE SKIP LOCKED` (the `scheduler::claim_due` pattern, `scheduler::next_run` for cron), render, store in object storage, mail through the existing outbox with an attachment (`email::queue_invoice` is the model; large files become links via `attachment_links`).
- Runs are pruned after 400 days.

**API:**

- `GET|POST /report-schedules`
- `GET|PUT|DELETE /report-schedules/{id}`
- `POST /report-schedules/{id}/run`
- `GET /report-schedules/{id}/runs`
- `GET /report-runs/{id}/download`

Technicians manage their own; admins manage all. Audit `report_schedule.*`, `report.sent`. Not in the public API.

**UI:** `/reports` gains a "Scheduled" tab and a "Schedule…" button on each report tab, with a drawer (presets weekly, monthly, quarterly; recipients picker; history with download).

**Tests:**

- Unit: range resolution at month and quarter edges in a time zone; recipient rules.
- e2e (in `billing`/`portal_and_sla`): schedule, "run now", and `smtp_sink` gets a mail with a `%PDF` attachment for a user and a contact; a contact on a profitability report is 400; the owner loses access and the run is `failed` with the reason; cron sets `next_run_at`.
- Visual: the tab and drawer.

### D3. On-call and paging (feature 10)

**Scope in:**

- On-call schedules with rotations and overrides.
- Escalation policies.
- A notification channel kind `oncall` that pages instead of broadcasting.
- Channel kinds `sms` (Twilio-compatible), `pagerduty` and `opsgenie`.
- Per-user contact methods; acknowledge from a link.

**Scope out:** voice calls; inbound SMS replies ("ACK"); two-way sync from PagerDuty/Opsgenie (acknowledgements made there); fairness reports.

**Decision: paging is a channel kind.** Alert items already choose channels per item and per set, so "critical alerts on servers page on-call after hours" is an alert item whose `channel_ids` includes an `oncall` channel. No second routing engine.

**Data model (0046):**

- `notification_channels.kind` CHECK widened to add `sms`, `pagerduty`, `opsgenie`, `oncall`. Secrets go in the existing sealed `secret` column.
  - `sms`: `{to: [E.164…]}`
  - `pagerduty`: `{}` plus the routing key
  - `opsgenie`: `{region: us | eu}` plus the API key
  - `oncall`: `{escalation_policy_id, when: always | outside_hours, calendar_id}`. `outside_hours` uses `business_calendars` from the SLA feature.
- `company_settings`: `sms_account_sid`, `sms_from`, `sms_base_url` (default `https://api.twilio.com`), `sms_token_enc`, `sms_token_sealed`.
- `users.phone`, `users.phone_verified_at`.
- `oncall_schedules (id, name, timezone)`.
- `oncall_layers (id, schedule_id, position, name, user_ids uuid[], start_at, shift_hours, restrict jsonb)`. `restrict` is weekday and time-of-day windows.
- `oncall_overrides (id, schedule_id, user_id, starts_at, ends_at, created_by)`.
- `escalation_policies (id, name, repeat)`.
- `escalation_steps (policy_id, position, delay_minutes, targets jsonb)`. Targets are `{schedule}`, `{user}` or `{channel}`.
- `pages (id, alert_id, ticket_id, policy_id, step, round, status, next_escalation_at, acked_by, acked_at, created_at)`.
- `page_deliveries (id, page_id, user_id, method, status, attempts, next_attempt_at, error, provider_ref)`.
- `user_contact_rules (user_id, method, delay_minutes)`.
- `company_settings.p1_escalation_policy_id` (optional: page on a new P1 ticket).

**Server** (`src/oncall.rs`):

- `who_is_on_call(schedule, at)`: a pure function. Layers by position, the highest matching wins; overrides win over layers.
- `trigger(alert | ticket, policy)`; `run()` every 15 seconds escalates due pages and drains `page_deliveries` with `notify::backoff`.
- `ack(page, user)`.
- Acknowledging or resolving the alert acknowledges or resolves the page, and the reverse (hooks in `api/alerts.rs` and `alerts::announce`).

`notify.rs` changes:

- `validate_config`, `Channel::open` and the sender gain the three external kinds.
- An `oncall` row in the outbox calls `oncall::trigger` instead of sending.
- PagerDuty: Events API v2, `dedup_key` is the alert id, `trigger` on opened and `resolve` on resolved.
- Opsgenie: create with `alias`, close on resolved.
- SMS: `POST {base}/2010-04-01/Accounts/{sid}/Messages.json`. The message is at most 300 characters and carries a short link `/a/<token>` (a single-use, 24-hour token that opens the alert page; it still requires a session to act).
- Endpoint overrides for tests: `RMM_PAGERDUTY_URL`, `RMM_OPSGENIE_URL`.

**API** (`api/oncall.rs`):

- `/oncall/schedules` CRUD
- `GET /oncall/schedules/{id}/shifts?from&to`
- `GET /oncall/now`
- `POST|DELETE /oncall/overrides`
- `/oncall/escalation-policies` CRUD
- `GET /oncall/pages`, `POST /oncall/pages/{id}/ack`
- `GET|PUT /account/contact-methods`, `POST /account/phone/verify`
- `GET|PUT /settings/sms`

Public API: `getOnCallNow`, group `alerts`.

**RBAC and audit:** a new `Perm::OncallManage` (`oncall.manage`, default admin) for schedules and policies. Any technician may create an override that puts *themselves* on. Audit `oncall.*`, `page.ack`.

**UI:**

- Settings → On-call (`/settings/oncall`): a schedule timeline with layers and overrides; an escalation editor.
- Settings → Notifications: forms for the new kinds, with Test.
- Account → "How to reach me".
- A "On call now" chip on `/alerts` and the dashboard.
- A paging timeline on `/alerts/[id]`.

**Tests:**

- Unit: rotation maths across DST changes, restrictions, overrides, layer precedence; the escalation state machine; SMS body length; payload shapes.
- e2e `oncall` with mock HTTP sinks: a critical alert leads to an SMS to the on-call user; no acknowledgement leads to step 2 (delays shortened with `RMM_ONCALL_MINUTE_SECS`); an acknowledgement stops it; a resolve sends the PagerDuty resolve and the Opsgenie close; `outside_hours` holds a page inside business hours; the SMS token is sealed and survives `rotate-data-key`.
- Visual: schedules, policy editor, alert timeline.

**Risks:** SMS deliverability and sender registration (A2P 10DLC) are the operator's job; document in OPERATOR.md. Real Twilio, PagerDuty and Opsgenie are unproven here.

### D4. Technician mobile access: PWA (feature 14)

**Scope in:**

- An installable PWA (manifest, service worker for the app shell).
- Web Push for alerts, pages and ticket events, with an Acknowledge action.
- Phone layouts checked and fixed for alerts, tickets and time.
- A bottom tab bar when installed.

**Scope out:**

- A native app.
- Offline data and queued offline writes: never cache API responses, they hold client data.
- Biometric app lock.
- Remote desktop and terminal tuning for phones.

**Data model (0047):**

- `push_keys (id boolean PRIMARY KEY, public bytea, private bytea, private_sealed boolean)`: the VAPID pair, made at first use.
- `push_subscriptions (id, user_id, endpoint UNIQUE, p256dh, auth, user_agent, created_at, last_ok_at, failures)`.
- `user_notification_prefs (user_id, event, push, email)`. Events: `alert_critical`, `alert_warning`, `page`, `ticket_assigned`, `ticket_reply`, `sla_warning`.

**Server** (`src/push.rs`):

- RFC 8291 (`aes128gcm`) and RFC 8292 (VAPID ES256) implemented with `ring`, already a dependency (ECDH P-256, HKDF, AES-128-GCM, ECDSA). No new crate.
- The endpoint host must be a known push service (`fcm.googleapis.com`, `*.push.services.mozilla.com`, `*.notify.windows.com`, `*.push.apple.com`); otherwise a user could aim the server at any URL. A test-only override, `RMM_PUSH_ALLOW_HOSTS`, exists.
- 404 or 410 deletes the subscription.
- The payload is small: title, body, `url`, `alert_id`, `tag`. A per-user "hide details" option sends a generic body.
- Hooks: the `oncall` delivery method `push`; `notify::enqueue` (alerts, to users who can see the client and opted in); the existing staff mail points in `email.rs` (`queue_assigned`, `queue_client_message`, `queue_sla`).

**Web:**

- `src/service-worker.ts` (SvelteKit's built-in): precache `build` and `files`, network-only for `/api`, an offline page, `push` and `notificationclick` handlers. The Acknowledge action calls `POST /api/alerts/{id}/ack` with the session cookie.
- `GET /manifest.webmanifest` served by the server from branding (name, colours, icons resized from the branding icon).
- `app.html`: manifest link, `theme-color`, `apple-touch-icon`.
- The CSP in `vite.config.ts` already has `default-src 'self'`, which covers `worker-src` and `manifest-src`; verify in the browser.
- A `BottomNav.svelte` shown under `display-mode: standalone` (Alerts, Tickets, Time, Devices, More).
- Account → Notifications (enable on this device, per-event switches, a hint that iOS needs "Add to Home Screen" on iOS 16.4 or later).
- A sweep of `/alerts`, `/alerts/[id]`, `/tickets`, `/tickets/[id]`, `/time` at 390 px: 44 px targets, sticky action bar, timer start/stop.

**API:** `GET /push/key`, `POST|DELETE /push/subscriptions`, `GET|PUT /account/notification-prefs`, `POST /push/test`. Session-only.

**Tests:**

- Unit: the RFC 8291 Appendix A vector; the VAPID JWT verified with the public key; the host allow-list.
- e2e `push`: subscribe with a test key pair to a local sink, raise a critical alert, and the sink receives `Content-Encoding: aes128gcm` and `Authorization: vapid …`; the test decrypts the body; a 410 removes the subscription; a user without access to the client gets nothing.
- Playwright: a `mobile` project (390×844) with baselines for alerts, alert, tickets, ticket, time and the bottom bar; axe on each; the manifest is valid and the service worker registers.

**Risks:** real browser push (Chrome, Safari, Firefox) is manual. Notification text passes through third-party push services, but encrypted end to end.

---

## Phase E: vulnerabilities (feature 3)

**Decisions:**

- **Feeds:**
  - OSV per-ecosystem dumps for Linux packages: Debian, Ubuntu, AlmaLinux, Rocky Linux, Red Hat, SUSE/openSUSE, Alpine.
  - The Arch security tracker (`security.archlinux.org/issues/all.json`) for pacman.
  - NVD API 2.0 for Windows applications, restricted to products we have mapped.
  - CISA KEV and EPSS for priority.
  - Distro feeds, not NVD, for Linux: they account for backported fixes.
- **Mirror locally, not live lookups.** The server syncs daily into Postgres, only for ecosystems present in the fleet. Reasons: no inventory leaves the instance; no per-request rate limits at 10,000 agents; deterministic tests. Air-gapped installs use `rmm-server vuln-import <dir>`. Feed URLs are overridable (`RMM_VULN_OSV_URL`, `RMM_VULN_ARCH_URL`, `RMM_VULN_NVD_URL`, `RMM_VULN_KEV_URL`, `RMM_VULN_EPSS_URL`); the NVD key is `RMM_NVD_API_KEY` (an environment variable, so no sealed column).
- **Windows names are mapped by a curated table, never fuzzy-matched to CPE.** A wrong match destroys trust in the whole list. Unmapped titles are shown as "not assessed" with a button to map them.
- **The Windows OS itself is out:** missing KBs with severity are already patch management.

**Scope out:**

- Language ecosystems (npm, PyPI) and container images.
- Windows OS CVEs (MSRC CVRF).
- macOS.
- Exploit or configuration checks (CIS); a network vulnerability scanner.
- Ubuntu Pro/ESM entitlement awareness.

**Inventory changes** (agent and proto, all `#[serde(default)]`):

- `Software.source_name: Option<String>`: dpkg `${source:Package}`, rpm from `%{SOURCERPM}`. OSV's Debian and Ubuntu data is keyed by source package.
- rpm versions with epoch: `%{EPOCHNUM}:%{VERSION}-%{RELEASE}`.
- `SystemInfo.os_id` and `os_version_id` from `/etc/os-release` (`ID`, `VERSION_ID`), to derive the ecosystem (`Debian:12`, `Ubuntu:24.04:LTS`, `Rocky Linux:9`).

Agents that predate this are "not assessed: update the agent".

**Version matching** (`rmm-server/src/vuln/version.rs`): comparers for dpkg (epoch, upstream, revision, `~`), rpm (`rpmvercmp` plus epoch), apk, pacman (`vercmp`), and a dotted-numeric one for Windows and NVD ranges (`versionStart/EndIncluding/Excluding`). Unit-tested against the vectors in dpkg's and rpm's own test suites.

**Data model (0048):**

- `vuln_feeds (name PK, enabled, last_sync_at, last_modified, etag, records, error)`.
- `vulns (id text PK, aliases text[], cve text, summary, severity, cvss real, epss real, kev boolean, published, modified, source)`.
- `vuln_ranges (vuln_id, ecosystem, package, introduced, fixed, last_affected)`, index on `(ecosystem, package)`.
- `vuln_products (id, vendor, product, name_patterns text[], publisher_pattern, package_id REFERENCES software_packages)`, seeded from `content/vuln/products.json` (about 150 common Windows applications); admin-editable.
- `vuln_findings`, primary key `(agent_id, vuln_id, package)`: `installed_version`, `fixed_version`, `fix_available`, `first_seen`, `last_seen`, `resolved_at`.
- `vuln_acceptances (id, vuln_id, client_id, agent_id, note, expires_at, by)`.
- `agents.vuln_evaluated_at`, `agents.vuln_inventory_hash`, and stored counts `vuln_critical`, `vuln_high`.

**To keep the table and the noise bounded**, a finding is stored only when a fix exists, or severity is high or critical, or the CVE is in KEV. Distro feeds list hundreds of minor unfixed issues per host.

**Server** (`src/vuln/{mod,feeds,osv,nvd,arch,version,matcher}.rs`):

- `feeds::run()` daily: stream-unzips the OSV `all.zip` into `vuln_ranges` in batches; NVD incrementally by `lastModStartDate` for mapped CPE products; KEV and EPSS by CVE alias.
- `matcher::evaluate(agent)`: reads the inventory JSON, looks up ranges by `(ecosystem, source_name or name)`, upserts findings and resolves ones that went away. It runs when the inventory hash changes (hook in `agent_ws::store_inventory`) and for affected packages after a sync, in a bounded queue. No `agent_software` table is needed.
- `alerts::vulns_changed(agent)`.

**Remediation:**

- A Linux finding with a fixed version links to the device's pending patch for that package (`patches` row by name) with Approve/Install.
- A Windows finding whose product maps to a catalog package offers "Upgrade with <package>" through the existing `POST /software/deploy {op: "upgrade"}`; otherwise "Add to catalog".
- A `latest` software policy item is the standing fix.

**Alert kind `vulnerability`:** `{min_severity: "critical", kev_only: false, fix_available_only: true, older_than_days: 14, min_epss: null}`. **One alert per device**, with counts and the top five CVEs in `details`, not one per CVE. Added to `ALERT_KINDS`.

**API** (`api/vulns.rs`):

- `GET /vulnerabilities` (paged; by CVE, with device counts; filters client, severity, kev, fix, q)
- `GET /vulnerabilities/{id}`
- `GET /vulnerabilities/{id}/devices`
- `GET /agents/{id}/vulnerabilities`
- `GET /vulnerabilities/software`
- `POST|DELETE /vulnerabilities/acceptances`
- `GET /vulnerabilities/feeds`, `POST /vulnerabilities/sync`
- `/vulnerabilities/products` CRUD
- `GET /vulnerabilities/unassessed`

Perms: read `security.read`; accept `security.respond`; products, feeds and sync `security.manage`. Audit `vuln.accept`, `vuln.product.*`, `vuln.sync`. Public API: the four GET lists, group `security`.

**UI:**

- `/vulnerabilities` (sidebar under Security) with tabs By CVE, By device, By software, Not assessed.
- `/vulnerabilities/[id]`: description, CVSS, EPSS, KEV badge, affected devices, remediation actions, accept risk.
- A Vulnerabilities tab on the agent.
- A stat on the client overview and dashboard.
- Settings → Security → Vulnerability feeds (status, attribution).
- The `AlertForm` kind; a QBR block.

**Tests:**

- Unit: the comparers; OSV, NVD and Arch record parsing (`tests/fixtures/vuln/`); ecosystem derivation from os-release; the matcher on a synthetic inventory; the storage rule.
- e2e `vulnerabilities` with a mock feed server:
  - the test reads a real package and version from the agent's inventory and serves a record that affects exactly it, in that host's ecosystem (works on Ubuntu CI and an Arch dev box);
  - a finding appears, then the alert, then health changes;
  - a record with the fix at or below the installed version produces nothing;
  - KEV and EPSS are applied;
  - acceptance closes the alert and expires;
  - the Windows path uses a seeded inventory row and a product mapping against a mock NVD;
  - client scoping holds.
- Visual: list, CVE page, agent tab, feeds.

**Risks:**

- Feed size and first-sync time: Debian and Ubuntu dumps are large, so stream them and show progress.
- Red Hat's OSV coverage and package naming need checking against a real RHEL host.
- Windows mapping coverage is whatever the curated table covers; say so in the UI.
- Attribution texts for NVD ("not endorsed or certified by the NVD") and OSV belong on the feeds page.

---

## Phase F: identity

### F1. Identity management (feature 12)

**Scope in:**

- Per client, one or more directories: **Active Directory** through an agent on a domain controller, and **Entra ID** through Graph.
- List users and groups.
- Unlock (AD), reset password, disable and enable, remove from groups, revoke sessions (Entra).
- Onboarding and offboarding checklists as ticket templates.

**Scope out:**

- Creating users; licence assignment; group creation; mailbox conversion.
- Google Workspace.
- Self-service password reset from the portal.
- GPO management; hybrid writeback handling. A synced user (`onPremisesSyncEnabled`) is acted on in AD; the Entra action is disabled with an explanation.

**The existing Graph code is mailbox-only** (`graph.rs`: a per-mailbox app registration with Mail permissions). Extract the client-credentials token call into `graph::app_token(tenant, client_id, secret)` and add `src/entra.rs`.

Each client connection is an app registration **in the customer's tenant**:

- Read: `User.Read.All`, `Group.Read.All`.
- Actions: `User.ReadWrite.All` plus the **User Administrator** directory role on the app's service principal. Graph does not let an app reset passwords on application permissions alone.

**AD goes through a dedicated message, not a script job:** job bodies and output are stored, and a password must not be.

**Data model (0049):**

- `identity_sources`: `id`, `client_id`, `kind` (`ad`/`entra`), `name`, `agent_id` (AD), `tenant_id`, `app_client_id`, `secret bytea`, `secret_sealed boolean`, `sync_minutes`, `last_sync_at`, `last_error`, `high_usn`.
- `identity_users`: `id`, `source_id`, `external_id` (SID or object id), `username`, `upn`, `display_name`, `email`, `enabled`, `locked`, `privileged`, `synced_from_ad`, `last_logon_at`, `password_last_set`, `password_expires_at`, `mfa_registered`, `department`, `title`, `contact_id`, `deleted_at`, `synced_at`.
- `identity_groups`, `identity_group_members`.

**Proto** (`rmm-proto/src/identity.rs`, capability `identity_ad`, advertised only where `ProductType` is `LanmanNT`):

- `ServerMsg::Identity { request_id, op }` → `AgentMsg::IdentityReply { request_id, reply }`, awaited with the `hub.tool` pattern (a oneshot with timeout).
- Ops: `Sync { since_usn, page }`, `Unlock { sid }`, `ResetPassword { sid, password, must_change }`, `SetEnabled { sid, enabled }`, `RemoveFromGroups { sid, group_sids }`.

**Agent** (`src/identity/{mod,ad,fake}.rs`):

- One fixed embedded PowerShell script per op, using the ActiveDirectory module that is present on DCs.
- Arguments arrive as **JSON on stdin**, never interpolated.
- SIDs are checked against `^S-1-5-21-\d+-\d+-\d+-\d+$`.
- The password is read from stdin into a `SecureString`.
- Refused always: RID 500 and 502 (Administrator, krbtgt).
- Debug: `RMM_IDENTITY_FAKE=<file>`.

**Server** (`src/identity.rs`):

- A sync loop per source: AD delta by `uSNChanged`; Entra full list with `$select`, paged.
- Users are matched to `contacts` by email.
- Actions dispatch by source kind.
- Reset: the server generates the password, or takes the technician's. The outcome is exactly one of:
  - "show once": returned in the response with `Cache-Control: no-store`, stored nowhere;
  - "save to vault": `vault::put_managed(kind = identity, reference = "<source>:<external id>")`.
- `must_change` defaults to true.

**API** (`api/identity.rs`):

- `GET|POST /clients/{id}/identity-sources`
- `PUT|DELETE /identity-sources/{id}`
- `POST /identity-sources/{id}/test`, `POST /identity-sources/{id}/sync`
- `GET /clients/{id}/identity/users` (paged; filters locked, disabled, stale, no_mfa, q)
- `GET /identity/users/{id}`
- `POST /identity/users/{id}/{unlock|reset-password|disable|enable|revoke-sessions|remove-groups}`
- `GET /clients/{id}/identity/groups`

**RBAC and audit:**

- New `Perm::IdentityRead` and `Perm::IdentityManage` (default technician). `manage` needs 2FA, as the vault does.
- Privileged accounts (`adminCount = 1`, or Entra directory-role members) need an admin.
- Sources are admin-only.
- Actions are rate-limited (a new `identity_action` limiter).
- Audit `identity.unlock`, `identity.reset_password` (target, how it was delivered, never the value), `identity.disable`, `identity.enable`, `identity.revoke_sessions`, `identity.source.*`.
- **Not in the public API**, like the vault.

**Ticket templates and checklists (0050).** There are no ticket templates today, only canned responses, macros and ticket types. Add:

- `ticket_templates (id, name, client_id, board_id, type_id, priority, subject, body, checklist jsonb)`.
- `ticket_checklist_items (id, ticket_id, position, text, action, action_state, done_by, done_at)`.
- `tickets.identity_user_id`.

A checklist item is a manual tick-off, optionally with an action button bound to the ticket's identity user: `identity.disable`, `identity.reset_password`, `identity.remove_groups`, `identity.revoke_sessions`. Seed two templates, "New starter" and "Leaver". Completing an item writes an internal timeline event (`tickets::add_event`).

The automations module is the wrong shape for this: it is a device event triggering a script.

Routes: `/ticket-templates` CRUD (admin), `POST /tickets/from-template`, `GET|PUT /tickets/{id}/checklist`.

**UI:**

- A "Users" tab on the client page (`components/identity/{UserList,UserDrawer,ResetDialog,SourceForm}.svelte`).
- The same actions from a ticket's contact panel when the contact is linked.
- Settings → Service desk → Templates.
- A Checklist panel on `/tickets/[id]`.

**Tests:**

- Unit: parsers for recorded `Get-ADUser`/`Get-ADGroup` JSON and Graph pages; SID validation; privileged detection; "exactly one delivery of a reset password".
- e2e `identity`:
  - AD through the fake: sync; unlock; reset to vault (reveal equals what the fake got); reset shown once (in no table and not in `audit_log`); disable.
  - RID 500 is refused; a privileged user needs an admin; another client's technician gets 404.
  - Entra through the existing `graph_mock()`, extended: list, disable, reset, revoke.
  - The leaver template creates a ticket whose checklist action disables the user and logs to the timeline.
- Visual: user list, drawer, reset dialog, checklist.

**Risks:** nothing here runs against a real DC or tenant on this box. Graph permission and role requirements must be verified on a real tenant before release (add to roadmap block 2). AD replication delay after an unlock is the customer's topology.

### F2. MDM, scoped down (feature 13)

**In:** a read-only view of **Intune managed devices** through the client's Entra connection from F1, with the extra permission `DeviceManagementManagedDevices.Read.All`.

**Data model (0051):** `mdm_devices`: `id`, `source_id`, `external_id`, `name`, `user_upn`, `os`, `os_version`, `compliance`, `encrypted`, `ownership`, `serial`, `model`, `manufacturer`, `enrolled_at`, `last_sync_at`, `agent_id`. `agent_id` is matched by serial number, else hostname.

**Server:** `entra::sync_devices` (`GET /deviceManagement/managedDevices`, paged) in the source's sync loop, behind a per-source switch.

**API:** `GET /clients/{id}/mdm/devices` (paged; filters compliance, os, unmatched), `GET /mdm/devices/{id}`. Read needs `identity.read`. Public API: `listMdmDevices`, group `agents`.

**UI:** a "Mobile and Intune" tab on the client page with a compliance badge, last check-in, owner, a link to the matched agent, and two gap lists: "in Intune, no agent" and "agent, not in Intune".

**Tests:** unit parse; e2e with the Graph mock (sync, matching, scoping); visual for the tab.

**Cut, deliberately:**

- Remote actions (wipe, retire, lock, sync): destructive, need `…PrivilegedOperations.All`, and nobody has tested Graph against a real tenant yet.
- Compliance and configuration policy authoring; app deployment.
- Apple MDM (APNs certificate, ABM/DEP, VPP, declarative management) and Android Enterprise (EMM registration, managed Play): each is a product on its own with vendor enrolment and device labs.
- Our own MDM server.
- Alerts on non-compliance: possible after step C1b; not in the first cut.

---

## Phase G: end-user tray app (feature 8)

**Architecture decision:**

- **A subcommand of the existing binary**, `rmm-agent tray`, running **as the signed-in user** in their session. It talks to the service over a local socket. This is the remote-desktop helper's pattern (a separate process per session with framed MessagePack), with two differences: the tray is long-lived and it is *not* SYSTEM.
- **Started by:**
  - Windows: an `HKLM\…\Run` value written by the MSI (`api/msi.rs` Registry table) and by `rmm-agent install`.
  - Linux: `/etc/xdg/autostart/rmm-tray.desktop` plus a launcher in `/usr/share/applications`, both from the deb/rpm.
- **IPC:**
  - Windows: named pipe `\\.\pipe\rmm-agent-tray` with a DACL for Interactive users; the peer is identified with `GetNamedPipeClientProcessId` and its session and user.
  - Unix: socket `/run/rmm-agent/tray.sock` with `SO_PEERCRED`.
  - Frames are u32-LE length plus MessagePack, enums `TrayToAgent` and `AgentToTray` in `rmm-agent/src/tray/ipc.rs`.
- **GUI toolkit:**
  - **Windows: raw Win32 through the `windows` crate already in the tree** (`Shell_NotifyIconW`, a popup menu, a small dialog). No new dependency; tens of kilobytes.
  - **Linux v1: no persistent tray icon.** The launcher opens the request form with zenity or kdialog, which the consent prompt already uses. A StatusNotifierItem icon needs a D-Bus stack (`zbus`, roughly a megabyte); defer it. Linux desktops are a small share of MSP fleets.
  - macOS waits for the platform.
  - Rejected: Tauri/WebView2 and egui. They add megabytes, a second build pipeline, or a runtime dependency.

**The tray is untrusted.** Any local user can open the pipe. The service accepts only:

- read the contact card and branding;
- submit a help request (5 an hour per user, text at most 5,000 characters, screenshot at most 5 MiB);
- answer a consent prompt addressed to *that* session.

Nothing privileged, no paths, no commands.

**Scope in:**

- "Request help": subject, description, optional screenshot; opens a ticket linked to the device with context.
- A branded contact card.
- Consent prompts shown by the tray when one is connected for the session (fallback: today's `WTS`/zenity prompt).
- A "technician connected" notice during a desktop session.
- Configurable links.

**Scope out:**

- Chat.
- Self-service script catalogue.
- The Linux SNI icon; macOS.
- Screenshots on Wayland.
- Annotating screenshots.

**Data model (0052):**

- Policy module `tray`, single-instance, seed item `…000000000007`: `{enabled: true, request_help: true, contact_card: true, screenshot_default: true, links: [{label, url}]}`.
- `tickets.source_ref text` with a partial unique index (idempotent offline resends).
- `company_settings.tray_board_id`.

**Proto** (`rmm-proto/src/tray.rs`, capability `tray`):

- `ServerMsg::TrayConfig(Config { enabled, product_name, icon_png, contact: {name, phone, email, url, hours}, links, request_help, screenshot_default })`: on connect and on policy or branding change; the agent caches it on disk so the card works offline.
- `AgentMsg::HelpRequest { request_id, user, session, subject, body, context, screenshot_len }`, then `AgentMsg::HelpAttachment { request_id, offset, data, done }` (the `TriageChunk` pattern).
- `ServerMsg::HelpRequestResult { request_id, ticket_number, error }`.

**Agent** (`src/tray/{mod,ipc,server,win,linux,request}.rs`):

- The service side listens, rate-limits, forwards, and keeps up to three unsent requests in the state directory for when the socket is down. Network trouble is a prime reason to ask for help.
- The tray side captures the screenshot *before* the dialog opens, reusing `desktop/win.rs` GDI capture and `desktop/x11.rs`, encoded with `desktop/encode.rs`.
- After a self-update the service sends `AgentToTray::Restart`.
- A headless mode, `rmm-agent tray --request --subject … --body … [--screenshot file]`, drives the same IPC (for tests and for scripts).

**Server** (`src/helpdesk_agent.rs`, hook in `agent_ws.rs`):

- Creates the ticket through the path `portal::create_ticket` uses: client from the agent; contact matched by UPN or email when the agent could determine one, else the requester text "jsmith on HOST".
- Board: `tray_board_id`, else `portal_board_id`.
- Source `agent`; `ticket_agents` link; screenshot as an attachment.
- A context block as the first internal note: OS, uptime, logged-in user, IP, open alerts.
- Idempotent on `source_ref = request_id`.
- Server-side limit: 20 a day per device.

**API:** no new public routes; `/settings/service-desk` gains `tray_board_id`. Audit `ticket.create` with `source: agent`.

**UI:** `TrayForm.svelte` in the policy set; a ticket source badge "From device"; the Settings → Branding preview shows the contact card.

**Tests:**

- Unit: the IPC codec, the limiter, size caps, peer identity parsing, request persistence.
- e2e `tray` (Linux): the headless CLI over the real Unix socket leads to a ticket with the attachment, the agent link and context; a sixth request in the hour is refused; a request made while the server is down arrives once after reconnect; `TrayConfig` reflects a client branding override.
- Windows e2e: the same CLI over the named pipe; the Run key exists after MSI install and is gone after uninstall.
- The Win32 dialog, icon and consent prompt are manual: add a section to `windows-testing.md`.

**Risks:** a pipe open to all interactive users is new attack surface on a SYSTEM service. Keep the parser tiny, fuzz the frame decoder, and include it in the external security review. Terminal servers run one tray per session; the peer's session id routes prompts.

---

## What can only be compile-checked or unit-tested here

The dev box is Linux. Windows is clippy-checked through mingw in Docker and runs in CI on `windows-latest`. The `rust` CI job's matrix includes `macos-latest`, so macOS code is at least built there.

| Piece | Here | Still unproven |
|---|---|---|
| BitLocker status and escrow | parsers on recorded output; e2e with the fake; Windows CI sees an unencrypted `C:` | a real BitLocker volume, TPM, Group Policy restrictions |
| FileVault, Time Machine | parsers on recorded output; built on the macOS runner | everything at run time |
| LUKS | real `lsblk` on the dev box and CI; fixtures | |
| LAPS, Windows | real on `windows-latest` (admin runner) | domain-joined machines, Windows LAPS coexistence, localised Windows |
| LAPS, Linux | fake in e2e (the agent isn't root there); unit | the real `chpasswd` path; run once by hand as root |
| Script parameters | real on Linux and Windows CI | |
| Uptime | real (local listeners) | ICMP on Windows (`IcmpSendEcho`) beyond the runner |
| Backup: Veeam, WSB | recorded event XML and JSON | real products |
| Backup: restic, borg | real in CI when installed | |
| Wake-on-LAN | packet bytes received on loopback | an actual machine waking; switches that drop directed broadcasts |
| SMS, PagerDuty, Opsgenie | mock HTTP sinks | the real services |
| Web Push | RFC vectors; mock endpoint | Chrome, Safari and Firefox delivery; iOS installed PWA |
| CVE feeds | fixtures and a mock feed server | full-size real feeds (run one manual sync before release); RHEL naming |
| AD | fake directory; recorded PowerShell output | a real domain controller |
| Entra, Intune | the e2e Graph mock | a real tenant, the role requirement for password resets |
| Tray | IPC and headless CLI on both OSes | the Win32 GUI, multi-session hosts, UAC and secure-desktop interplay |
| White-label | MSI properties read back, PDF structure, visual baselines | how real mail clients and Windows "Apps & features" show it |

Add every "still unproven" row to roadmap blocks 1 and 2 and to `docs/design/windows-testing.md`.

## Cut or deferred

| Item | Reason |
|---|---|
| Turning BitLocker/FileVault/LUKS on | Reboots, TPM states and user impact; a script with parameters covers the careful case |
| FileVault and LUKS key escrow | Not readable or addable unattended without user credentials or MDM |
| macOS local admin rotation | Password on argv; SecureToken and keychain breakage |
| Server-run uptime in the first cut | Needs alerts without an agent (about 36 queries); shipped as step C1b |
| Vendor backup cloud APIs | Each is an integration with its own auth and data model; `file_age` and event logs cover most |
| Wake for unmanaged devices and for software windows | Little demand; easy to add later |
| Report builder, CSV/XLSX, portal report downloads | The four existing reports first |
| Voice calls, inbound SMS acknowledgements, two-way PagerDuty/Opsgenie sync | Need public inbound webhooks and signature checks; link and push acknowledgement cover v1 |
| Offline writes in the PWA; a native app | Conflict handling and cached client data on phones |
| Language-ecosystem and container CVEs, Windows OS CVEs, fuzzy CPE matching | Noise and false positives; the OS is covered by patching |
| Creating users, licences, Google Workspace, portal self-service resets | Write paths with billing and security consequences; after the read and reset paths are proven on real tenants |
| Intune actions, Apple and Android MDM, our own MDM | Vendor programmes, device labs and destructive actions |
| Linux tray icon, macOS tray, Wayland screenshots | Dependency weight and platform status |
| Per-client console theming, custom CSS, renaming binaries and service ids | Breaks upgrades and self-update; little value |
| Redacting secrets from job output | Unreliable across chunk boundaries; documented instead |

## Cross-cutting checklist for each feature PR

- Migration with the next number; `upgrade.rs` still passes from `v0.2.0`.
- Proto additions are `#[serde(default)]` or behind a capability; an old agent and a new server, and the reverse, both work (covered by the `upgrade` job and a unit round-trip).
- New agent messages added to the kind index in `agent_ws.rs`; new workers spawned in `main.rs`.
- Sealed columns listed in `rotate::TABLES`, and covered by the `key_rotation` e2e section (`sealed_values`).
- Public operations added to `api::public::OPS` only where this plan says so; the registry tests still pass.
- Audit events named `<area>.<verb>`; the SIEM stream carries them without change.
- Visual baselines and axe for every new page, light and dark, desktop and (from D4) mobile.
- README, OPERATOR.md (new environment variables), CHANGELOG `[Unreleased]`, FEATURES.md, and a design record per feature under `docs/design/` once built.

---

### Critical Files for Implementation

- `/home/sean/NAS/DATA/coding/RMM/crates/rmm-proto/src/lib.rs`: `AgentMsg`/`ServerMsg`, `ScriptJob`, `Inventory`, `Software`, `SystemInfo`; every feature adds messages or fields here.
- `/home/sean/NAS/DATA/coding/RMM/crates/rmm-server/src/alerts.rs`: `Rule` enum, `policies_for`, `announce`; every new alert kind, and the agentless-alert refactor.
- `/home/sean/NAS/DATA/coding/RMM/crates/rmm-server/src/policy.rs`: `Module`, per-module configs, `validate`, `clean_override`, `ALERT_KINDS`; new modules and schedule/automation `params`.
- `/home/sean/NAS/DATA/coding/RMM/crates/rmm-server/src/api/vault.rs`: `client_key`/`seal`/`open` to extract into the shared `vault.rs` write path, plus the reveal hook for LAPS.
- `/home/sean/NAS/DATA/coding/RMM/crates/rmm-server/src/notify.rs`: channel kinds, outbox worker; SMS, PagerDuty, Opsgenie, on-call and push hooks.

