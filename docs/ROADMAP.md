# Roadmap

Last reviewed 2026-11-22.

## Where things stand

| Phase | Status |
|---|---|
| 1. Core | Done |
| 2. Hardening | Done; Windows paths proven only on GitHub's runners (block 1) |
| 3. UI redesign | Done |
| 4. Monitoring and alerting | Done |
| 5. Patch management | Done |
| 6. Remote desktop | v1 done (X11 and Windows GDI) |
| 7. PSA | Done: service desk, portal, SLAs, time, contracts, billing, documentation and password vault |
| 8. Endpoint protection | Milestones 1-7 done, plus our own antivirus engine ([design](design/antivirus.md)) on Linux; Windows real-time collection not built, Windows and macOS sensor untested |
| 9. Policy management | Done ([design](design/policies.md)) |

Everything built works end to end on Linux and is covered by unit tests, the e2e suite (`crates/rmm-server/tests/e2e.rs`), the Windows e2e on `windows-latest`, the `upgrade` job and the Playwright visual and accessibility tests. The biggest gap is still that **no Windows code path has run on a real Windows host**, and Windows is where most MSP fleets are.

**CI:** main was fully green on `505b405` (2026-11-20, all nine jobs, including `e2e-windows` and `upgrade` for the first time on GitHub). It has been red since `cfd816e` because of the `upgrade` job only; see block 0.

Design records: [PSA](design/psa.md), [endpoint protection](design/endpoint-protection.md), [antivirus](design/antivirus.md), [production readiness](design/production-readiness.md), [policy management](design/policies.md), [documentation and vault](design/documentation.md), [UI survey](research/rmm-ui-survey.md), [load test](research/load-test-2026-11.md).

## Next

In priority order. Block 1 waits on Windows hardware and the security review waits on a reviewer; work on the next block meanwhile. Each block should be finished and usable before the next starts.

### 0. Green main and a release

- [ ] **Fix the `upgrade` job.** `tests/upgrade.rs` now seeds documentation pages with `POST /api/clients/{id}/docs`, but the previous release it runs against (`v0.1.1`, 2026-11-10) predates documentation, so the seed fails with 405. Seed the docs rows only when the old server has the route (or insert them in SQL the way `0023` expects to find them), so the job checks the `0023` migration once a release with docs exists.
- [ ] **Cut `v0.2.0`.** Nothing has been tagged since `v0.1.1`: blocks 3-6, policy management, the docs and vault and the antivirus engine are only on main. A tag gives the `upgrade` job a newer starting point, gives agents a stable release to update to, and gives operators something other than `main` to pin. Add a CHANGELOG while doing it, and a short release checklist (tag, image, signed agent builds, upgrade job green).

### 1. Windows on real hosts

Every Windows feature is compile-checked (clippy via mingw) and unit-tested against recorded output. The Windows e2e (`crates/rmm-server/tests/e2e_windows.rs`, the `e2e-windows` job) already covers the MSI install, upgrade and uninstall, the service and its recovery actions, the data-directory ACL, PowerShell and cmd jobs, the Job Object tree kill, results across a service restart and the service list. Run the rest on Windows 10/11 and Server 2019/2022, and keep it running:

- [ ] Extend the Windows e2e to self-update, ConPTY shells, Event Log watchers, patches, Defender and the sensor.
- [ ] Install and service on a real host: the `C:\ProgramData\RMM` ACL, the Program Files copy, SCM recovery actions, file logging, reinstall over a running service, MSI upgrade and repair.
- [ ] Self-update: service stop/start from the detached watchdog, and rollback.
- [ ] Jobs and shells (ConPTY, Job Objects), service list and control (`Win32_Service`), Event Log watchers (`wevtutil`).
- [ ] Patches: WUA scan and install, the `PSWindowsUpdate` fallback, reboot handling.
- [ ] Remote desktop: session-0 helper, `Winlogon`/UAC desktop switching, `SendSAS`, multi-monitor DPI, RDP sessions.
- [ ] Security: Defender, Security Center with a third-party product, passive mode; the sensor's process/network polling, quarantine, Windows Firewall isolation.
- [ ] Fix what breaks, and record the tested versions in the README.

### 2. Before the first real customer

- [ ] **Security review** by someone outside the project: agent/server protocol, enrollment, the update and content signing chain, session handling, per-client scoping, the shell and desktop relays, the client portal, and the password vault (envelope encryption, reveal auditing, rate limits).
- [ ] **`RMM_DATA_KEY` rotation**: a CLI command that rewraps the vault's client keys and reseals TOTP secrets, mailbox and accounting secrets and detection context under a new key. Today a leaked key can't be replaced without losing that data.
- [ ] **Backups cover everything.** The nightly `pg_dump` misses local object storage (attachments, invoice PDFs, triage packages). Back it up beside the dump (or document that S3 must be versioned), and add a restore drill to CI: restore a dump and the storage into an empty stack and read the e2e's rows back.
- [ ] **Stored columns for search and health** (from the [load test](research/load-test-2026-11.md)): agent search scans every inventory's JSON (~0.8 s at 10,000 agents) and dashboard health is computed per request (~0.3 s, refetched on every alert, job and online change). These are the first things to give at 10,000 agents.
- [ ] **Try the integrations against the real services**, not stand-ins: AWS S3 and MinIO (multipart uploads and ranges), Microsoft 365 over Graph, QuickBooks Online (sandbox company), Xero (demo organisation), and how real mail clients render our emails.
- [ ] **Operator guide**: TLS and reverse proxy, sizing from the load test, the environment variables that must be kept safe (`RMM_DATA_KEY`, signing keys), monitoring with `/metrics`. Most of it is in the README already; gather it into one install path an MSP can follow.

### 3. Platform: API, SSO and organisation

- [ ] **API keys and a public REST API** with OpenAPI docs, scoped by permission set and client. Webhooks out for ticket and alert events. Other tools and the PSA integrations below build on it.
- [ ] **SSO for technicians**: OIDC first (Entra ID and Google cover most MSPs), SAML later. Map groups to roles and clients. Passkeys (WebAuthn) as a second factor.
- [ ] **Tags, custom fields and agent notes**, then **saved views** built on the existing URL state. Custom fields can be filled by scripts (script output → field), which is how MSPs track things we don't collect.
- [ ] **Automation policies**, the rest of them: scheduled scripts and an alert's `run_script_id` already live in policy sets. Left: run on enrollment and other event triggers, and a script that runs once per device rather than on a timetable.
- [ ] Audit log export and a syslog/SIEM stream.

### 4. Reach: more devices and platforms

- [ ] **Software deployment**: winget and Chocolatey on Windows, apt/dnf on Linux, MSI push; doubles as third-party patching. Lives in policy sets like patching.
- [x] **Network discovery** from an agent (ICMP/TCP sweep, neighbour table, reverse DNS, mDNS, SNMP `sysDescr`) to find unmanaged devices, and **SNMP monitoring** (v2c and v3) for switches, firewalls and printers through a designated agent, with device-down, interface-down and threshold alerts. Design: [design/network.md](design/network.md). Not yet: traps, LLDP/CDP topology, vendor MIBs, IPv6 scans.
- [ ] **Windows real-time protection** (antivirus milestone 6): ETW for process starts and file writes instead of polling, scan on write and on start, and an AMSI provider for script content. Two earlier attempts stopped before any code was written; notes are in [design/antivirus.md](design/antivirus.md). Needs block 1's hosts to test on.
- [ ] **macOS as a supported platform**: launchd install, a signed and notarised `.pkg`, launchd services and the unified log, ScreenCaptureKit + `CGEvent` remote desktop, the Endpoint Security framework for the sensor. Pieces exist (patches, XProtect); the platform as a whole doesn't.
- [ ] Remote desktop on Wayland (GNOME Mutter RemoteDesktop/ScreenCast, then the portal for KDE/wlroots).
- [ ] Horizontal scaling: route hub messages over Postgres LISTEN/NOTIFY or NATS so several server nodes share agents. One node holds 10,000 agents, so do it when a customer needs more.

## Later

Worth doing, but not until the above is in place:

- **UI:** undo on cheap actions and optimistic toggles; a peek drawer from the agents list; favourites; configurable dashboard widgets; script version history.
- **Monitoring:** TimescaleDB if Postgres with rollups stops keeping up.
- **Patches:** Arch security data (`arch-audit`), Ubuntu Pro/ESM, Windows feature-update targeting.
- **Remote desktop:** clipboard sync and file drop; remote cursor shape; H.264 with hardware encoders and DXGI capture; WebRTC peer-to-peer with TURN fallback; session recording to object storage, a "being watched" indicator and view-only sessions.
- **Endpoint protection:** ClamAV on-access detections and the XProtect Remediator log; mass-encryption detection beyond decoys (fanotify, minifilter/ETW file events); rollback of Run keys, services and scheduled tasks; a measured performance budget on low-end hardware and an adversary-emulation lab run; a licensed hash/threat-intel feed; ingesting detections from other EDRs. Replacing Defender outright (minifilter, ELAM, MVI) needs a decision and money first.
- **PSA:** two-way calendar sync for the schedule; Stripe payment links on invoices; per-client purge of closed tickets for GDPR requests. Tax calculation stays with the accounting system by design.
- **Integrations:** HaloPSA, ConnectWise Manage and Autotask sync for MSPs keeping their own PSA; asset warranty lookups; M365 licence counts for per-user contracts.

## Done

Summaries of what each phase built. The commits have the full detail.

### Phase 1: Core

Multi-tenant model (clients → sites → agents), RBAC and audit log; token enrollment with per-agent secrets over an outbound-only WebSocket; metrics with history and charts; hardware and software inventory (dpkg/rpm/pacman, Windows registry); script library and ad-hoc scripts (bash, sh, PowerShell, cmd, Python) with bulk runs and offline queueing; web terminal (PTY/ConPTY); systemd and Windows service install; dashboard SPA.

### Phase 2: Hardening and production readiness

- Enrollment can't take over an existing agent without its secret; agents detect dead connections; refuse plain `http://` except localhost.
- Jobs survive reconnects, server restarts and agent restarts (results buffered until `JobAck` and persisted in `job-results`); queued jobs expire after `RMM_JOB_QUEUE_DAYS`; Unix shells kill their session on close, Windows jobs and shells use Job Objects.
- Security headers and a hash-based script-src CSP; Windows state directory restricted to SYSTEM and Administrators; privileged file handling hardened against links and path tricks.
- Accounts: password change and reset, session list and revoke, idle timeout; TOTP 2FA with recovery codes, secrets sealed with `RMM_DATA_KEY`; rate limits on sign-in and enrollment; per-client access control.
- Signed agent self-update (ed25519, `rmm-sign`) with a watchdog that rolls back; manual, bulk and automatic rollout, with builds from main numbered as pre-releases and a sweep that offers releases to online agents.
- Per-token `.deb`/`.rpm`/`.msi` packages (the MSI written by the server, no WiX); nightly Postgres backups in the compose stacks.
- Production readiness ([design](design/production-readiness.md)): attachments up to `RMM_ATTACHMENT_MAX_MB`, streamed to local or S3 storage, with links for large email attachments; `/metrics` and JSON request logs; the load generator (`crates/rmm-loadgen`) and a load test holding 10,000 agents on one node; the `upgrade` CI job that migrates the previous release's data and reruns the e2e on it.

### Phase 3: UI redesign

Design tokens with light/dark themes, bundled fonts and a component library on Bits UI (`web/src/lib/ui/`, gallery at `/dev/ui`); grouped sidebar, client switcher, command palette; keyset paging, filters and sorting with all state in the URL; live updates over SSE; a server-computed health model; WCAG 2.2 AA checked by axe in CI, phone layouts, keyboard shortcuts, and Playwright visual regression in Docker. Later refreshed with a navy rail and Geist.

### Phase 4: Monitoring and alerting

Alert policies (offline, CPU/memory/disk thresholds, services, failed jobs, event-log matches, patches, security) with severities feeding health; open → acknowledged → resolved lifecycle; notification channels (email, webhook with HMAC, Slack, Teams) through a Postgres outbox; service monitoring and control; journald / Windows Event Log watchers; cron-scheduled scripts in any time zone; hourly metric rollups. Day-to-day additions: maintenance windows and snoozes, re-notify, process list with kill, file browser and transfer, bulk actions on every row matching a filter, package managers in their own systemd scope.

### Phase 5: Patch management

A `PatchProvider` per OS: Windows Update Agent COM API (PSWindowsUpdate fallback), apt, dnf/yum, pacman, softwareupdate. Scan and install with results resent after reconnects, reboot policies, approvals that stand for agents reporting later, auto-approval by severity/category, deferral, maintenance windows, retries, compliance and history; missing updates and pending restarts count against health.

### Phase 6: Remote desktop (v1)

Frames over the agent WebSocket, relayed by the server. A helper in the user's session, GDI and MIT-SHM capture, `SendInput` and XTEST input, consent prompts, 64×64 tile diff with JPEG per band, quality presets, ack-based flow control, monitor picker and Ctrl+Alt+Del. Decided against for v1: H.264 (openh264 licensing, agent size) and DXGI (GDI works on every desktop, including the secure one).

### Phase 7: PSA

- **Service desk:** contacts and email domains; boards and statuses; P1-P4 from impact × urgency; tickets with an append-only timeline, attachments, merge and bulk edits; full-text search; linked agents with actions from the ticket; outbound email threaded by Message-ID; inbound IMAP, provider webhooks and Microsoft 365 over Graph; alert → ticket with dedupe and flap protection; teams, canned responses and macros, CSAT surveys.
- **Portal and SLAs:** the client portal (`/portal`) with emailed links or password plus TOTP, tickets, public KB and device status; SLA policies per priority with business calendars, pausing, warnings and breaches.
- **Time, contracts and billing:** permission sets for billing and approval; time entries, timers and timesheets; rate lookup; device, user, block-hour, T&M and recurring contracts; invoice runs with gapless numbers, PDFs, credit notes and email; QuickBooks Online and Xero sync; scheduling, projects with phases and burn-down, reports and a QBR PDF per client.
- **Documentation and password vault** ([design](design/documentation.md)): Markdown pages with categories, templates, revisions, an in-page editor and `.md` import/export; a per-client vault with envelope encryption under `RMM_DATA_KEY`, audited and rate-limited reveals, password history and TOTP codes; pages linked to tickets.

### Phase 8: Endpoint protection

- **Status and management:** Defender plus Windows Security Center, ClamAV and XProtect state; scans and signature updates from the console; a `security` alert policy kind with stale-state alerts.
- **Sensor** (separate process supervised by the agent): file scanning, quarantine and restore, exclusions; process, network, file, autorun and module telemetry; a behaviour rule engine with 27 starter rules; response (kill tree, quarantine, isolate host, triage package); investigation UI with process tree, timeline, hunting and hash prevalence; prevention with canary rollout, automatic rollback and a kill switch.
- **Own antivirus engine** ([design](design/antivirus.md)): hash and YARA (boreal) scanning, signed signature databases, Linux on-access blocking with fanotify, fleet reputation and a console.

### Phase 9: Policy management

One model instead of four ([design](design/policies.md), [API](design/policies-api.md)): device categories, one tree of policy sets with per-field overrides, assignments per client and site, single-device pins. Alert policies, scheduled scripts, patching, security, remote access and agent updates all live in sets; the old per-feature tables are gone, and `0022_policies.sql` migrates them.
