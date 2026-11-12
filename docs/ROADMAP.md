# Roadmap

Last reviewed 2026-11-12.

## Where things stand

| Phase | Status |
|---|---|
| 1. Core | Done |
| 2. Hardening | Done on Linux; MSI, Job Objects, persisted job results and sealed TOTP secrets added; Windows e2e passing in CI (see Next) |
| 3. UI redesign | Done |
| 4. Monitoring and alerting | Done |
| 5. Patch management | Done |
| 6. Remote desktop | v1 done (X11 and Windows GDI) |
| 7. PSA | Milestones 1-7 done (blocks 4 and 6 below); password vault not built |
| 8. Endpoint protection | Milestones 1-7 done; Windows and macOS sensor untested |

What's built works end to end on Linux and is covered by unit tests, the e2e suite (`crates/rmm-server/tests/e2e.rs`) and the Playwright visual and accessibility tests. The biggest gap is that **no Windows code path has run on a real Windows host.** Windows is where most MSP fleets are, so that comes first.

Design records: [PSA](design/psa.md), [endpoint protection](design/endpoint-protection.md), [UI survey](research/rmm-ui-survey.md).

## Next

In priority order. Each block should be finished and usable before the next starts.

### 1. Windows on real hosts

Every Windows feature is compile-checked (clippy via mingw) and unit-tested against recorded output only. Run them all on Windows 10/11 and Server 2019/2022, and keep them running:

- [ ] **Windows e2e in CI.** GitHub's `windows-latest` runners can install a service, run Defender and query Windows Update. Run the real agent as a service there against a server in the job, so regressions show up without a lab.
  - Written: `crates/rmm-server/tests/e2e_windows.rs` and the `e2e-windows` CI job (server and Postgres on the runner, agent installed from the generated MSI). It covers the MSI install/upgrade/uninstall, the service and its recovery actions, the data-directory ACL, PowerShell and cmd jobs, the Job Object tree kill, results across a service restart and the service list. Passing in CI since 2026-11-12. The first runs found that msiexec rejected the package (version 4 compound file, UTF-8 code page) and that a running job kept the service from stopping; both fixed.
  - Still to add: self-update, ConPTY shells, Event Log watchers, patches, Defender, the sensor.
- [ ] Install and service: the `C:\ProgramData\RMM` ACL, the Program Files copy, SCM recovery actions, file logging, reinstall over a running service.
- [ ] Self-update: service stop/start from the detached watchdog, and rollback.
- [ ] Jobs and shells (ConPTY), service list and control (`Win32_Service`), Event Log watchers (`wevtutil`).
- [ ] Patches: WUA scan and install, the `PSWindowsUpdate` fallback, reboot handling.
- [ ] Remote desktop: session-0 helper, `Winlogon`/UAC desktop switching, `SendSAS`, multi-monitor DPI, RDP sessions.
- [ ] Security: Defender, Security Center with a third-party product, passive mode; the sensor's process/network polling, quarantine, Windows Firewall isolation.
- [ ] Fix what breaks, and record the tested versions in the README.

### 2. Before the first real customer

- [x] **MSI installer** with the server URL and token baked in, like the `.deb`/`.rpm`. Built by the server with the `msi` and `cab` crates rather than WiX (`crates/rmm-server/src/api/msi.rs`), so there's no Windows toolchain. Silent install, major upgrades, keeps the enrollment on upgrade/repair (`enroll --keep-existing`), removes the service on uninstall. Installed, upgraded and uninstalled on `windows-latest` by the Windows e2e above; not yet on a real (non-CI) Windows host.
- [x] **Windows Job Objects** for jobs and shells (`crates/rmm-agent/src/winjob.rs`). Jobs: a timeout kills the tree, but what a script leaves running survives it, as on Unix. Shells: kill-on-close, so closing the terminal kills everything started from it. Compile-checked only.
- [x] **Persist the agent's job buffer to disk** (`job-results` in the state directory): results survive an agent restart, and a job that was running when the agent stopped is reported as `error` with its output instead of `lost`.
- [x] **Encrypt TOTP secrets at rest** with `RMM_DATA_KEY` (`users.totp_sealed`); plaintext rows are sealed at startup, and the server refuses to start if sealed secrets exist but the key is missing. `RMM_DATA_KEY` is required by both production compose files.
- [ ] **Attachments and uploads over 8 MB** (agent file uploads stream since block 3; ticket and portal attachments are still under the 8 MB request limit): a per-route body limit or chunked upload, instead of the global request limit.
- [ ] **Load test the server**: simulate 1,000 and 10,000 agents (metrics, heartbeats, jobs, SSE clients) and record CPU, memory, Postgres size per agent per day, and alert evaluation time. Sets the honest per-node limit and tells us whether horizontal scaling (below) is urgent.
- [ ] **Server observability**: a Prometheus `/metrics` endpoint (connected agents, hub queue depths, outbox backlog, alert eval duration, request latency) and JSON logs.
- [ ] **Upgrade path**: a CI job that migrates a database built by the previous release and runs the e2e suite against it. Document backup → upgrade → rollback in the README.
- [ ] **Security review** by someone outside the project: agent/server protocol, enrollment, the update and content signing chain, session handling, per-client scoping, the shell and desktop relays.

### 3. Day-to-day gaps MSPs will hit first

Small items from earlier phases that technicians notice quickly. Done 2026-11-12 (migration `0015_day_to_day.sql`); covered by unit tests, the e2e suite and the visual tests.

- [x] Maintenance windows / snooze per agent for alerts, re-notify while an alert stays open, and per-agent policy overrides (exclude one machine from a client-wide policy). `alert_mutes` (one-off or weekly, per client, site or agent); alerts opened during one are `suppressed` (no notifications, tickets or health) and announced when it ends. Policies have `renotify_minutes` and `excluded_agents`.
- [x] Patches in health and alerts: missing critical updates (over a week) and pending restarts (over a day) count against health; a `patch` alert policy for failed installs and long-pending restarts. Approvals made for a client, site or everything stand for agents reporting the update later (`patch_approvals`).
- [x] Alert when an agent stops reporting its protection state (`stale_hours` on the security policy; agents now resend an unchanged state hourly).
- [x] Run package managers in their own systemd scope, so restarting the agent mid-install doesn't kill dpkg. Output goes to files, not pipes. Not yet run as root under systemd: unit-tested for the file output only.
- [x] Agent page: a grouped side sub-nav instead of the tab strip (a scrolling strip on phones).
- [x] Bulk actions on every row matching a filter: "Select all N matching" on the agents, alerts and tickets lists (up to 5,000, sent to the bulk endpoints in batches).
- [x] Process list with kill, outside of a detection (agent's Processes section; the agent's own and system processes are protected).
- [x] File browser and transfer: browse, download (streamed) and upload (no 8 MB limit, written next to the target and moved into place when complete) over the agent socket in 512 KB pieces. New agent capability `tools`.

### 4. PSA milestones 3-4: portal and SLAs

Done 2026-11-12 (migration `0016_portal_sla.sql`); covered by unit tests and the e2e suite (`portal_and_sla`). See [design/psa.md](design/psa.md).

- [x] **Client portal** (`/portal`): contact sign-in by emailed one-time link, or a password plus optional TOTP; sessions in their own table with a cookie scoped to `/api/portal`, so neither session type reaches the other's API. Tickets (own, or all of the client's for primary contacts), replies and new requests with attachments, "mark resolved", public KB articles (all clients or one), and a device status list when the client allows it. Invitations and credential resets from the client's Contacts tab.
- [x] **SLA engine**: policies with respond / update / resolve targets per priority, business calendars (time zone, opening hours, holidays) or around the clock, default and per-client policies (an active contract's first). Deadlines and 75% points are stored on the ticket; the clock pauses in Waiting on client and Resolved; warnings and breaches go to the policy's channels, the assignee and the timeline. List sorting by due, "SLA missed" and "Due soon" views.
- [x] Left over from milestones 1-2: Microsoft 365 mailboxes over Graph (receive and send; app secret sealed with `RMM_DATA_KEY`), teams (assignment, board defaults, "My teams"), split a message into a new ticket, canned responses and macros with variables, CSAT surveys (one-click links, results on the ticket and in reports), per-board new-ticket notifications.
- Not run against real Microsoft 365 or real mail clients' rendering yet: the Graph flow is tested against a stand-in of the token, list, `$value`, mark-read and `sendMail` endpoints.

### 5. Platform: API, SSO and organisation

- [ ] **API keys and a public REST API** with OpenAPI docs, scoped by permission set and client. Webhooks out for ticket and alert events. Other tools and the PSA integrations below build on it.
- [ ] **SSO for technicians**: OIDC first (Entra ID and Google cover most MSPs), SAML later. Map groups to roles and clients. Passkeys (WebAuthn) as a second factor.
- [ ] **Tags, custom fields and agent notes**, then **saved views** built on the existing URL state. Custom fields can be filled by scripts (script output → field), which is how MSPs track things we don't collect.
- [ ] **Automation policies**: run scripts on enrollment, on a schedule or when an alert opens (self-healing), per client/site/OS like the other policies.
- [ ] Audit log export and a syslog/SIEM stream.

### 6. PSA milestones 5-7: time, contracts and billing

Done 2026-11-12 (migration `0017_billing.sql`); covered by unit tests and the e2e suite (`billing`).

- [x] Permission sets `billing.read`, `billing.manage`, `time.approve` (admins by default); technicians log time and sell catalog items without seeing rates. Time entries and a timer on tickets, projects or clients; work types and roles; rate lookup (contract override → work role → work type → technician → company); contract types per device (agent count snapshotted, workstations/servers), per user, block hours (bank, overage, low-balance warning), time and materials, recurring with items; covered work types; weekly timesheets with submit / approve / reject.
- [x] Invoice runs (calendar-aligned cycles, prorated by day, each cycle billed once), draft editing, finalisation with gapless numbers and a stored PDF (our own small PDF writer, no dependency), email to billing contacts with the PDF, paid / void, credit notes. Currency per client (company default). QuickBooks Online and Xero: OAuth connect, push invoices, credit notes and customers, pull payment status every 10 minutes.
- [x] Scheduling (who, when, linked to a ticket or project), projects with phases and tasks (task → ticket) and budget burn-down, client documentation with revisions, reports (service desk, utilisation, profitability) and a QBR PDF per client. Billing contacts see invoices in the portal.
- Not done: the password vault (needs its own design and security review), tax calculation (left to the accounting system by design), payment links. QuickBooks and Xero are tested against stand-ins of their OAuth and API endpoints, not the real services: try a QuickBooks sandbox company and a Xero demo organisation before relying on it.

### 7. Reach: more devices and platforms

- [ ] **Software deployment**: winget and Chocolatey on Windows, apt/dnf on Linux, MSI push; doubles as third-party patching.
- [ ] **Network discovery** from an agent (ARP/ping sweep, mDNS, SNMP sysDescr) to find unmanaged devices, and **SNMP monitoring** for switches, firewalls and printers through a designated agent.
- [ ] **macOS as a supported platform**: launchd install, a signed and notarised `.pkg`, launchd services and the unified log, ScreenCaptureKit + `CGEvent` remote desktop, the Endpoint Security framework for the sensor. Pieces exist (patches, XProtect); the platform as a whole doesn't.
- [ ] Remote desktop on Wayland (GNOME Mutter RemoteDesktop/ScreenCast, then the portal for KDE/wlroots).
- [ ] Horizontal scaling: route hub messages over Postgres LISTEN/NOTIFY or NATS so several server nodes share agents. Do it when the load test says so.

## Later

Worth doing, but not until the above is in place:

- **UI:** undo on cheap actions and optimistic toggles; a peek drawer from the agents list; favourites; configurable dashboard widgets; script version history.
- **Monitoring:** TimescaleDB if Postgres with rollups stops keeping up.
- **Patches:** Arch security data (`arch-audit`), Ubuntu Pro/ESM, Windows feature-update targeting.
- **Remote desktop:** clipboard sync and file drop; remote cursor shape; H.264 with hardware encoders and DXGI capture; WebRTC peer-to-peer with TURN fallback; session recording to object storage, a "being watched" indicator and view-only sessions.
- **Endpoint protection:** ETW on Windows instead of polling; ClamAV on-access detections and the XProtect Remediator log; mass-encryption detection beyond decoys (fanotify, minifilter/ETW file events); rollback of Run keys, services and scheduled tasks; a measured performance budget on low-end hardware and an adversary-emulation lab run; a licensed hash/threat-intel feed; ingesting detections from other EDRs.
- **PSA:** a password vault (envelope encryption, reveal with audit and 2FA, its own security review); two-way calendar sync for the schedule; Stripe payment links on invoices; per-client purge of closed tickets for GDPR requests.
- **Integrations:** HaloPSA, ConnectWise Manage and Autotask sync for MSPs keeping their own PSA; asset warranty lookups; M365 licence counts for per-user contracts.

## Done

Summaries of what each phase built. The commit for each phase has the full detail.

### Phase 1: Core

Multi-tenant model (clients → sites → agents), RBAC and audit log; token enrollment with per-agent secrets over an outbound-only WebSocket; metrics with history and charts; hardware and software inventory (dpkg/rpm/pacman, Windows registry); script library and ad-hoc scripts (bash, sh, PowerShell, cmd, Python) with bulk runs and offline queueing; web terminal (PTY/ConPTY); systemd and Windows service install; dashboard SPA.

### Phase 2: Hardening

- Enrollment can't take over an existing agent without its secret; agents detect dead connections; refuse plain `http://` except localhost.
- Jobs survive reconnects and server restarts (agent buffers output and results until `JobAck`); queued jobs expire after `RMM_JOB_QUEUE_DAYS`; Unix shells kill their whole session on close.
- Security headers and a hash-based script-src CSP; Windows state directory restricted to SYSTEM and Administrators.
- Accounts: password change and reset, session list and revoke, idle timeout; TOTP 2FA with recovery codes (required for admins, optionally everyone); rate limits on sign-in and enrollment; per-client access control (`user_clients`).
- Signed agent self-update (ed25519, `rmm-sign`) with a watchdog that rolls back; manual, bulk and automatic rollout.
- Per-token `.deb`/`.rpm`/`.msi` packages; nightly Postgres backups in the compose stacks; the e2e integration suite in CI.
- Later additions: job results persisted on the agent (survive agent restarts), Windows Job Objects for jobs and shells, TOTP secrets encrypted with `RMM_DATA_KEY`.

### Phase 3: UI redesign

Design tokens with light/dark themes, bundled fonts and a component library on Bits UI (`web/src/lib/ui/`, gallery at `/dev/ui`); grouped sidebar, client switcher, command palette (`GET /api/search`); keyset paging, filters and sorting with all state in the URL; live updates over SSE (`GET /api/events`); a server-computed health model; rebuilt dashboard, agents, agent detail, clients, jobs, scripts (CodeMirror) and terminal pages; WCAG 2.2 AA checked by axe in CI, phone layouts, keyboard shortcuts, and Playwright visual regression in Docker. Decisions: no separate product name (company name is shown), theme follows the OS, mockups in code, SSE instead of a WebSocket.

### Phase 4: Monitoring and alerting

Alert policies per client/site/OS (offline, CPU/memory/disk thresholds, services, failed jobs, event-log matches, and later security) with severities feeding health; open → acknowledged → resolved lifecycle, one alert per (policy, agent, key). Notification channels (email, webhook with HMAC, Slack, Teams) through a Postgres outbox with retries. Service monitoring and control; journald / Windows Event Log watchers pushed to agents; cron-scheduled scripts in any time zone; hourly metric rollups (raw 7 days, rollups 90).

### Phase 5: Patch management

A `PatchProvider` per OS: Windows Update Agent COM API (PSWindowsUpdate fallback), apt, dnf/yum, pacman, softwareupdate. Scan and install with results resent after reconnects, reboot policies, and a self-updater that waits for installs. Server-side approvals, policies (auto-approve by severity/category, deferral, automatic install) MSP-wide, per client or per site, maintenance windows, retries; Patches page with compliance and history. apt, dnf5 and pacman were run for real in containers.

### Phase 6: Remote desktop (v1)

Frames over the agent WebSocket, relayed by the server. A helper process in the user's session (SYSTEM token moved to the console session on Windows; the X display owner on Linux), GDI and MIT-SHM capture, `SendInput` and XTEST input, consent prompts. 64×64 tile diff with JPEG per band, three quality presets, ack-based flow control. Audited, per-client consent, Remote desktop tab with monitor picker and Ctrl+Alt+Del. Decided against for v1: H.264 (openh264 licensing, agent size) and DXGI (GDI works on every desktop, including the secure one).

### Phase 7: PSA, milestones 1-2

Contacts and client email domains; boards with statuses mapped to categories; P1-P4 from impact × urgency; tickets with an append-only timeline, assignment, attachments, merge and bulk edits; full-text search; linked agents with live state and script/terminal/desktop actions from the ticket; local or S3 object storage; outbound email threaded by Message-ID and `[T-n]`; inbound IMAP and provider webhooks with threading and loop protection; alert → ticket with dedupe, auto-resolve and flap protection; auto-close of resolved tickets.

### Phase 8: Endpoint protection, milestones 1-7

- **Status and management:** Defender plus Windows Security Center, ClamAV and XProtect state; scans and signature updates from the console; a `security` alert policy kind; Security page and agent tab.
- **Prerequisites:** permission sets (`security.read/respond/manage`, `users.permissions`), signed content bundles verified on every agent, persisted sensor and response buffers, `RMM_DATA_KEY` encryption at rest for detection context.
- **Sensor** (separate process supervised by the agent): file scanning with hashes and rules, quarantine and restore, exclusions; process, network, file-of-interest, autorun and module telemetry in a local store queried from the console; a behaviour rule engine with 27 starter rules (audit mode by default), tests and a benign corpus; response (kill tree, quarantine, isolate host, triage package); investigation UI with process tree, timeline, hunting and hash prevalence; prevention only for proven rules, with canary rollout, automatic rollback and a fleet-wide kill switch.
- ClamAV was tested against real ClamAV 1.5.4; nftables/iptables isolation and the Linux process connector were tested as root.
