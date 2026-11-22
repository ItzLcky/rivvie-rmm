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

### Added

- **Network discovery and SNMP monitoring.** Each site chooses a designated agent. It scans its
  network (private ranges only, bounded) with ICMP where permitted, TCP probes, the neighbour
  table, reverse DNS, mDNS and SNMP `sysDescr`, and the dashboard lists what it finds under
  **Network**: hosts matched to agents by MAC or IP, and an unmanaged list with ignore, mark as
  known, monitor and deploy-an-agent actions. The same agent reads switches, routers, firewalls,
  printers, UPSes and NAS boxes over SNMP v2c and v3 (our own pure-Rust client: MD5, SHA-1 and
  SHA-2 authentication, DES and AES privacy): uptime, interface status and traffic, CPU, memory,
  disks, toner. Charts, hourly rollups, three alert kinds (device down, interface down,
  threshold) set up in policies, four read operations in the public API under a new `network`
  scope. SNMP credentials are per client, sealed under `RMM_DATA_KEY` (and resealed by
  `rotate-data-key`), and never shown again. Migration `0033`. See
  [docs/design/network.md](docs/design/network.md).

## [0.2.0] - Unreleased

The first release since agent self-update shipped. Everything below is new since `v0.1.1`.
Migrations `0014` to `0024` are new (the upgrade job migrates a `v0.1.1` database through them).

### Added

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

- **Web console redesign:** navy rail, Geist, refreshed design tokens, light and dark themes, a
  component library on Bits UI, grouped sidebar, client switcher and command palette.
- The agent shows the detail of a failed update on its page.
- Privileged file handling in the agent is hardened against links and path tricks.
- The project is licensed AGPL-3.0-or-later (licence text added).
- Workspace crates are versioned 0.2.0. Release agents take their version from the git tag
  (`RMM_AGENT_VERSION`), so this only changes what unreleased local builds report.

### Fixed

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
