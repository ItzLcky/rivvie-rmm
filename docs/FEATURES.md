# What is built

A summary of each phase, moved out of the [roadmap](ROADMAP.md) on 2026-11-24. Releases from `v0.1.1` on are in the [CHANGELOG](../CHANGELOG.md); the commits have the full detail.

## Phase 1: Core

Multi-tenant model (clients → sites → agents), RBAC and audit log; token enrollment with per-agent secrets over an outbound-only WebSocket; metrics with history and charts; hardware and software inventory (dpkg/rpm/pacman, Windows registry); script library and ad-hoc scripts (bash, sh, PowerShell, cmd, Python) with bulk runs and offline queueing; web terminal (PTY/ConPTY); systemd and Windows service install; dashboard SPA.

## Phase 2: Hardening and production readiness

- Enrollment can't take over an existing agent without its secret; agents detect dead connections; refuse plain `http://` except localhost.
- Jobs survive reconnects, server restarts and agent restarts (results buffered until `JobAck` and persisted in `job-results`); queued jobs expire after `RMM_JOB_QUEUE_DAYS`; Unix shells kill their session on close, Windows jobs and shells use Job Objects.
- Security headers and a hash-based script-src CSP; Windows state directory restricted to SYSTEM and Administrators; privileged file handling hardened against links and path tricks.
- Accounts: password change and reset, session list and revoke, idle timeout; TOTP 2FA with recovery codes, secrets sealed with `RMM_DATA_KEY`; rate limits on sign-in and enrollment; per-client access control.
- Signed agent self-update (ed25519, `rmm-sign`) with a watchdog that rolls back; manual, bulk and automatic rollout, with builds from main numbered as pre-releases and a sweep that offers releases to online agents.
- Per-token `.deb`/`.rpm`/`.msi` packages (the MSI written by the server, no WiX); nightly Postgres backups in the compose stacks.
- Production readiness ([design](design/production-readiness.md)): attachments up to `RMM_ATTACHMENT_MAX_MB`, streamed to local or S3 storage, with links for large email attachments; `/metrics` and JSON request logs; the load generator (`crates/rmm-loadgen`) and a load test holding 10,000 agents on one node; the `upgrade` CI job that migrates the previous release's data and reruns the e2e on it.

## Phase 3: UI redesign

Design tokens with light/dark themes, bundled fonts and a component library on Bits UI (`web/src/lib/ui/`, gallery at `/dev/ui`); grouped sidebar, client switcher, command palette; keyset paging, filters and sorting with all state in the URL; live updates over SSE; a server-computed health model; WCAG 2.2 AA checked by axe in CI, phone layouts, keyboard shortcuts, and Playwright visual regression in Docker. Later refreshed with a navy rail and Geist.

## Phase 4: Monitoring and alerting

Alert policies (offline, CPU/memory/disk thresholds, services, failed jobs, event-log matches, patches, security) with severities feeding health; open → acknowledged → resolved lifecycle; notification channels (email, webhook with HMAC, Slack, Teams) through a Postgres outbox; service monitoring and control; journald / Windows Event Log watchers; cron-scheduled scripts in any time zone; hourly metric rollups. Day-to-day additions: maintenance windows and snoozes, re-notify, process list with kill, file browser and transfer, bulk actions on every row matching a filter, package managers in their own systemd scope.

## Phase 5: Patch management

A `PatchProvider` per OS: Windows Update Agent COM API (PSWindowsUpdate fallback), apt, dnf/yum, pacman, softwareupdate. Scan and install with results resent after reconnects, reboot policies, approvals that stand for agents reporting later, auto-approval by severity/category, deferral, maintenance windows, retries, compliance and history; missing updates and pending restarts count against health.

## Phase 6: Remote desktop (v1)

Frames over the agent WebSocket, relayed by the server. A helper in the user's session, GDI and MIT-SHM capture, `SendInput` and XTEST input, consent prompts, 64×64 tile diff with JPEG per band, quality presets, ack-based flow control, monitor picker and Ctrl+Alt+Del. Decided against for v1: H.264 (openh264 licensing, agent size) and DXGI (GDI works on every desktop, including the secure one).

## Phase 7: PSA

- **Service desk:** contacts and email domains; boards and statuses; P1-P4 from impact × urgency; tickets with an append-only timeline, attachments, merge and bulk edits; full-text search; linked agents with actions from the ticket; outbound email threaded by Message-ID; inbound IMAP, provider webhooks and Microsoft 365 over Graph; alert → ticket with dedupe and flap protection; teams, canned responses and macros, CSAT surveys.
- **Portal and SLAs:** the client portal (`/portal`) with emailed links or password plus TOTP, tickets, public KB and device status; SLA policies per priority with business calendars, pausing, warnings and breaches.
- **Time, contracts and billing:** permission sets for billing and approval; time entries, timers and timesheets; rate lookup; device, user, block-hour, T&M and recurring contracts; invoice runs with gapless numbers, PDFs, credit notes and email; QuickBooks Online and Xero sync; scheduling, projects with phases and burn-down, reports and a QBR PDF per client.
- **Documentation and password vault** ([design](design/documentation.md)): Markdown pages with categories, templates, revisions, an in-page editor and `.md` import/export; a per-client vault with envelope encryption under `RMM_DATA_KEY`, audited and rate-limited reveals, password history and TOTP codes; pages linked to tickets.

## Phase 8: Endpoint protection

- **Status and management:** Defender plus Windows Security Center, ClamAV and XProtect state; scans and signature updates from the console; a `security` alert policy kind with stale-state alerts.
- **Sensor** (separate process supervised by the agent): file scanning, quarantine and restore, exclusions; process, network, file, autorun and module telemetry; a behaviour rule engine with 27 starter rules; response (kill tree, quarantine, isolate host, triage package); investigation UI with process tree, timeline, hunting and hash prevalence; prevention with canary rollout, automatic rollback and a kill switch.
- **Own antivirus engine** ([design](design/antivirus.md)): hash and YARA (boreal) scanning, signed signature databases, Linux on-access blocking with fanotify, fleet reputation and a console.

## Phase 9: Policy management

One model instead of four ([design](design/policies.md), [API](design/policies-api.md)): device categories, one tree of policy sets with per-field overrides, assignments per client and site, single-device pins. Alert policies, scheduled scripts, patching, security, remote access and agent updates all live in sets; the old per-feature tables are gone, and `0022_policies.sql` migrates them.

## Blocks 0-4 (2026-11-22, released in `v0.2.0` on 2026-11-23)

Built in parallel tracks and merged with full local checks (clippy incl. Windows, all tests, e2e with SNMP, restore drill, MinIO, 369 visual tests):

- **Release prep:** `upgrade` job fix, CHANGELOG, [release checklist](RELEASING.md), [operator guide](OPERATOR.md), 0.2.0 bump.
- **Production:** `rotate-data-key`; storage backed up beside the dump, restore script and CI drill; MinIO S3 test; stored search and health columns (`0026`); IMAP/SMTP/webhook secrets sealed (`0031`).
- **Platform:** OIDC SSO and passkeys (`0028`, [design](design/sso.md)); API keys, `/api/v1`, OpenAPI, webhooks (`0027`, [design](design/api.md)); tags, custom fields, notes, saved views (`0029`, [design](design/fields.md)); automations with event, tag, field and run-once triggers (`0030`, `0035`, [design](design/automations.md)); audit export and SIEM stream (`0031`, `0034`, [design](design/audit-siem.md)).
- **Reach:** software deployment (`0032`, [design](design/software.md)); network discovery and SNMP (`0033`, [design](design/network.md)); Windows e2e sections and a [real-host test plan](design/windows-testing.md).

Known gaps: no Windows run of any of it; SSO untested against real IdPs; no alerts for failed deployments; SNMP traps, LLDP and IPv6 scans not built; automations whose `field_value` no longer matches a select field's choices never fire.

## Parity features (unreleased)

- **End-user tray app** (`0052`, [design](design/tray.md)): `rmm-agent tray` as the signed-in user; request help (subject, description, screenshot) as a ticket linked to the device with a context note, the branded contact card and links, consent prompts and a "technician connected" notice; Windows icon, Linux launcher, headless `--request` for scripts; offline requests kept and sent once.
- **Wake-on-LAN** (`0043`, [design](design/wake-on-lan.md)): wake one device or many through an online agent at the site; optional wake before a patch window.
- **Scheduled reports** (`0045`, [design](design/scheduled-reports.md)): the four reports as PDFs on a timetable, emailed to users and contacts with the owner's access checked at run time; history and send now.
- **White-labelling** (`0044`, [design](design/branding.md)): instance branding with per-client overrides; product name, logos, icon, contrast-checked accent, support card, email sender and footer; branded MSI, packages, service name, consent prompt and PDF headers; an always-present AGPL source link.
- **Script parameters** (`0036`, [design](design/script-params.md)): typed parameters on saved scripts, passed as `RMM_PARAM_*` environment variables with per-device placeholders and built-ins; secrets sealed until delivery or taken from the vault.
- **Managed vault items** (`0037`, [design](design/vault-managed.md)): the system write path (`vault::put_managed`) that disk encryption escrow, LAPS and identity resets use.
- **On-call and paging** (`0046`, [design](design/oncall.md)): schedules, escalation policies, the `oncall` channel kind, text message, PagerDuty and Opsgenie channels.
- **Installable app and Web Push** (`0047`, [design](design/pwa.md)): manifest, service worker, push for alerts, pages and tickets, phone tab bar.
- **Uptime monitors** (`0040`, [design](design/uptime.md)): ping, TCP, HTTP(S) with keyword, TLS certificate and DNS checks run by an agent; availability, latency and certificate alerts. Server-run checks (step C1b) are not built yet.
- **Backup monitoring** (`0042`, [design](design/backups.md)): Windows Server Backup, Veeam, restic, Borg, Time Machine and backup files; failed and stale alerts.
