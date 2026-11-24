# Changelog

All notable changes to RMM are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases are numbered
[SemVer](https://semver.org/)-style: the git tag (`v0.2.0`) is the version agents report and
update to; see [docs/RELEASING.md](docs/RELEASING.md). Builds from `main` between tags are
pre-releases of the next patch (`0.2.1-dev.57` after `v0.2.0`).

Database migrations only go forward. Each release lists the newest migration it carries; to go
back, restore the backup taken before the upgrade (see
[docs/OPERATOR.md](docs/OPERATOR.md#upgrades)).

## [Unreleased]

Migrations `0046` and `0047` are new.

### Added

- **On-call and paging.** Schedules with rotation layers (handovers keep their local time across
  DST), restrictions and overrides; escalation policies with steps, delays and repeats; a
  notification channel kind `oncall` that pages through a policy (always, or only outside a
  business calendar's hours) instead of telling everyone; pages acknowledged from the console,
  a push notification or the short link in a text message, and acknowledging or resolving the
  alert stops them. New channel kinds: text message (Twilio-compatible), PagerDuty (Events API
  v2, resolved with the alert) and Opsgenie. Per-user contact rules and a verified mobile
  number; optional paging for new P1 tickets; an "On call now" chip and a paging timeline on
  alerts; `GET /api/v1/oncall/now`. New permission `oncall.manage`. See
  [docs/design/oncall.md](docs/design/oncall.md).
- **The dashboard as an installable app.** A web app manifest, a service worker for the app
  shell (API responses are never cached), Web Push for alerts, pages and ticket events with an
  Acknowledge action, per-event notification preferences (push and email) and a lock-screen
  privacy switch, and a tab bar at the bottom when installed on a phone. See
  [docs/design/pwa.md](docs/design/pwa.md).

## [0.2.0] - 2026-11-23

The first release since agent self-update shipped. Everything below is new since `v0.1.1`.
Migrations `0014` to `0035` are new (there is no `0025`) (the upgrade job migrates a `v0.1.1` database through them).

### Added

- **Single sign-on and passkeys.** OIDC sign-in for technicians (Entra ID and Google presets,
  any provider with discovery) with PKCE, IdP groups mapped to role, permissions and clients,
  optional JIT accounts and a require-SSO switch with break-glass admins; WebAuthn passkeys as a
  second factor beside TOTP. See [docs/design/sso.md](docs/design/sso.md).
- **API keys, public REST API and webhooks.** Scoped keys (`rmm_k_…`) for users and service
  accounts, never more than their owner; `/api/v1` with an OpenAPI 3.1 document at
  `/api/openapi.json` and a reference at `/developers`; HMAC-signed ticket and alert webhooks
  through the outbox, with a delivery log. See [docs/design/api.md](docs/design/api.md).
- **Tags, custom fields, agent notes and saved views.** Scripts set custom fields by printing
  `RMM-FIELD name=value`. See [docs/design/fields.md](docs/design/fields.md).
- **Automations.** Policy-set scripts triggered by enrollment, coming back online, a new alert,
  a pending reboot after patching, a tag being added or a custom field changing, and scripts
  that run once per device; with cooldowns, hourly limits and maintenance windows. See
  [docs/design/automations.md](docs/design/automations.md).
- **Software deployment.** A catalog of winget, Chocolatey, apt/dnf packages and uploaded
  MSI/EXE installers, deployed ad hoc or as desired state in policy sets, with third-party update
  reporting. See [docs/design/software.md](docs/design/software.md).
- **Network discovery and SNMP monitoring.** A designated agent per site sweeps its subnets and
  lists unmanaged devices; switches, firewalls and printers are polled over SNMP v2c/v3 with
  device-down, interface-down and threshold alerts. New `rmm-snmp` crate. See
  [docs/design/network.md](docs/design/network.md).
- **Audit export and SIEM stream.** CSV and JSON Lines export (new `audit.read` permission);
  audit events, detections and alerts streamed to syslog (UDP, TCP, TLS) or HTTPS JSON / Splunk
  HEC from a durable outbox. See [docs/design/audit-siem.md](docs/design/audit-siem.md).
- **`rmm-server rotate-data-key`** re-seals everything sealed with `RMM_DATA_KEY` in one
  transaction, with a dry run.
- **Complete backups.** `deploy/backup.sh` saves local object storage beside the database dump,
  `deploy/restore.sh` restores both, and the `restore-drill` CI job proves it. S3 storage is
  tested against MinIO (`s3` CI job).
- **Windows e2e sections** for ConPTY shells, Event Log watchers, patch scans, Defender, the
  sensor and self-update with rollback, and a manual real-host test plan
  ([docs/design/windows-testing.md](docs/design/windows-testing.md)).
- **PSA, the rest of it.** A client portal (`/portal`, emailed sign-in links or password plus
  TOTP) with tickets, public knowledge base and device status; SLA policies per priority with
  business calendars, pausing, warnings and breaches; time entries, timers and timesheets;
  device, user, block-hour, time-and-materials and recurring contracts; invoice runs with gapless
  numbers, PDFs, credit notes and email; QuickBooks Online and Xero sync; scheduling, projects
  with phases and burn-down; reports and a quarterly-review PDF per client.
- **Documentation and password vault.** Per-client Markdown pages with categories, templates,
  revisions, an in-page editor and `.md` import/export; a per-client vault with envelope
  encryption under `RMM_DATA_KEY`, audited and rate-limited reveals, password history and TOTP
  codes; pages linked to tickets. Existing free-text categories are migrated to category rows.
  See [docs/design/documentation.md](docs/design/documentation.md).
- **Policy management.** One model replaces four: device categories, one tree of policy sets
  with per-field overrides, assignments per client and site, and single-device pins. Alert
  policies, scheduled scripts, patching, security, remote access and agent updates all live in
  sets. `0022_policies.sql` migrates the old per-feature tables. See
  [docs/design/policies.md](docs/design/policies.md).
- **Our own antivirus engine.** Hash and YARA scanning from signed signature databases
  (`rmm-sign build-db`), Linux on-access blocking with fanotify, fleet reputation (alert only,
  never an automatic block) and a console. See [docs/design/antivirus.md](docs/design/antivirus.md).
- **Endpoint protection.** The sensor, its behaviour rule engine, response actions (kill tree,
  quarantine, isolate host, triage package), the investigation UI and prevention with canary
  rollout, rollback and a kill switch.
- **Agent auto-update from `main`.** Builds from `main` are numbered as pre-releases of the next
  patch and offered to connected agents; the server sweeps online agents for new releases.
- **Day-to-day tooling.** Maintenance windows and snoozes, patch health, process list with kill,
  file browser and transfer, bulk actions on everything a filter matches.
- **Production readiness.** Attachments up to `RMM_ATTACHMENT_MAX_MB`, streamed to local or S3
  storage, with links for large email attachments; Prometheus `/metrics` and JSON request logs;
  the load generator (`rmm-loadgen`) and a load test at 10,000 agents
  ([docs/research/load-test-2026-11.md](docs/research/load-test-2026-11.md)).
- **MSI packages** written by the server (no WiX), and Windows agent hardening: job persistence,
  Job Objects, sealed 2FA secrets (`RMM_DATA_KEY`).
- **CI.** The `upgrade` job (migrates the previous release's data and reruns the e2e suite on
  it), the Windows e2e on `windows-latest` (MSI install, upgrade and uninstall, service, jobs),
  and Playwright visual and accessibility tests.
- Operator guide ([docs/OPERATOR.md](docs/OPERATOR.md)), this changelog and the release
  checklist ([docs/RELEASING.md](docs/RELEASING.md)).

### Changed

- **Agent search and dashboard health read stored columns** (`pg_trgm` indexes and per-agent
  health kept current by triggers). At 10,000 agents search went from ~840 ms to ~16 ms and the
  dashboard from ~260 ms to ~50 ms. The migration needs the `pg_trgm` extension.
- **IMAP, SMTP and webhook-channel secrets are sealed** with `RMM_DATA_KEY`; they were stored in
  plaintext. A server holding sealed values refuses to start without the key. Change those
  passwords if old backups matter to you.
- **Web console redesign:** navy rail, Geist, refreshed design tokens, light and dark themes, a
  component library on Bits UI, grouped sidebar, client switcher and command palette.
- The agent shows the detail of a failed update on its page.
- Privileged file handling in the agent is hardened against links and path tricks.
- The project is licensed AGPL-3.0-or-later (licence text added).
- Workspace crates are versioned 0.2.0. Release agents take their version from the git tag
  (`RMM_AGENT_VERSION`), so this only changes what unreleased local builds report.

### Fixed

- Windows: typing `exit` in a web terminal now ends the session (ConPTY exit watcher); the update
  watchdog treats "service already running" as success instead of rolling back; the quarantine
  guard honours `%SystemRoot%`; uninstall removes `rmm-agent.old.exe` and `.new.exe`.
- The `upgrade` CI job no longer fails when the previous release predates documentation pages:
  the seed probes for the route and the e2e reads pages back only if any were created.
- Windows: agents stop promptly with a job running; MSIs are written as version 3 compound files
  with a Windows-1252 code page.
- Several e2e and CI deflakes (rollup check, sensor-crash lookup, reputation test programs).

## [0.1.1] - 2026-11-11

First signed agent release: agents update themselves to newer builds signed with the release key
(`rmm-sign`), with a watchdog that rolls back a build that cannot reconnect. Server image build
fixes (detection content copied into the build stages) and Windows path-exclusion fixes.

[Unreleased]: https://github.com/ItzLcky/rivvie-rmm/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ItzLcky/rivvie-rmm/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/ItzLcky/rivvie-rmm/releases/tag/v0.1.1
