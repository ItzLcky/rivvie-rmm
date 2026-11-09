# Roadmap

## Phase 1: Core (done)

- [x] Multi-tenant model (clients → sites → agents), RBAC, audit log
- [x] Token enrollment, per-agent secrets, outbound-only WebSocket transport
- [x] Metrics (CPU, memory, swap, disks, network, load) with 30-day history and charts
- [x] Inventory: hardware, disks, NICs, installed software (dpkg/rpm/pacman, Windows registry)
- [x] Script library and ad-hoc scripts (bash, sh, PowerShell, cmd, Python), bulk runs, offline queueing
- [x] Interactive web terminal (PTY / ConPTY)
- [x] systemd and Windows service install
- [x] Dashboard SPA

## Phase 2: Hardening (do before real customers)

Done:

- [x] Enrollment can't take over existing agents: a record is reused only when the agent proves its old secret; a bare token always creates a new record
- [x] Agent detects dead connections (100 s read timeout) and no longer waits for running jobs before reconnecting
- [x] Job lifecycle: in-flight jobs that can no longer report become `lost` (narrowed since: see job buffering below); queued jobs `expire` after `RMM_JOB_QUEUE_DAYS`
- [x] Agent refuses plain `http://` servers except localhost unless `--insecure`
- [x] Security headers: `frame-ancestors 'none'`, X-Frame-Options, nosniff, Referrer-Policy, HSTS when the public URL is https
- [x] systemd unit: dropped `MemoryMax=128M`/`Nice=10`, which every script and shell inherited
- [x] Windows: `C:\ProgramData\RMM` restricted to SYSTEM and Administrators (on enroll and every service start); job scripts written there instead of the shared temp dir
- [x] Windows: service binary copied to `C:\Program Files\RMM`, SCM restart-on-failure, file logging to `C:\ProgramData\RMM\logs\agent.log`
- [x] Account management: change password (signs out your other sessions), admin password reset (signs them out everywhere), re-enable users, list and revoke sessions. Sessions now expire after `RMM_SESSION_IDLE_HOURS` (default 12) of inactivity, within the 7-day cap.
- [x] Company settings page (admins only): company name shown in the sidebar, sign-in page and tab title; session idle timeout override. Users is a tab under it.
- [x] TOTP 2FA (RFC 6238, replay-protected) with 10 single-use recovery codes. Required for admins, and for everyone when Company settings says so: until it's set up, the session can only reach the 2FA setup endpoints. Admins can reset another user's 2FA; `rmm-server reset2fa --email` covers a locked-out sole admin. Secrets are stored unencrypted in Postgres, so a database leak exposes them.
- [x] Rate limiting: failed sign-ins per client IP (10, then one per 30 s) and per account (20, then one per 90 s); bad enrollment tokens per IP on the agent socket and token downloads (20, then one per 15 s). Only failures count, so mass rollouts behind one NAT aren't throttled. `X-Forwarded-For` is believed only from `RMM_TRUSTED_PROXIES`.
- [x] Per-client access control: `user_clients` plus `users.all_clients` (default on, so existing accounts are unchanged). Every agent, site, token, job, terminal and dashboard query is scoped, and out-of-scope ids read as 404. Scripts are global (`client_id` NULL, admin-only to edit) or per client (that client's technicians edit them; they only run on its agents). The client-portal role is deferred to Phase 7's separate contacts auth.
- [x] Jobs survive reconnects: the agent keeps each job's output (1 MB per stream) and result, resends them after reconnecting (`JobSync`, then `JobFinished`), and drops them once the server sends `JobAck`. Disconnects and server restarts no longer mark jobs `lost`. A job is `lost` only when the agent reconnects without it (it restarted) or the timeout reaper gives up.
- [x] Unix shells: closing a terminal sends SIGHUP to the shell's session, then SIGKILLs everything left in it (background jobs included)
- [x] Agent self-update: ed25519-signed releases (`rmm-sign`, kept off the server; the public key is compiled in with `RMM_UPDATE_PUBKEY`). Version, platform and SHA-256 are signed, and versions that aren't newer are refused. Download is chunked over the agent socket and staged, the agent waits for running jobs (30 min max), and the swap happens in a watchdog that runs from a copy of the old binary outside the service (a transient systemd unit, or a detached process on Windows). The watchdog rolls back if the new version doesn't authenticate within 120 s. Manual, bulk and automatic (Company settings) rollout; progress per agent on the dashboard. The Linux path is tested under systemd. The Windows path is compile-checked only.
- [x] `.deb`/`.rpm` packages generated per token with the server URL and token baked in (`/etc/rmm-agent/enroll.toml`, removed after enrollment); postinst enrolls and starts the service, upgrades keep the enrollment. Package tokens default to 30 days / 50 uses, and the server refuses to bake an unbounded token.
- [x] Script-src CSP: SvelteKit `kit.csp` in hash mode emits a `<meta>` policy (`script-src 'self'` plus the bootstrap hash); the server header keeps `frame-ancestors`
- [x] Postgres backups: a `backup` service in both compose stacks (nightly `pg_dump -Fc`, mode 0600, pruned after `BACKUP_KEEP_DAYS`); restore steps in the README
- [x] Integration tests: `crates/rmm-server/tests/e2e.rs` runs the real server against a scratch Postgres database with real agent processes. It covers enrollment reuse/takeover, jobs across a server restart, `lost`/`expired`, headers, 2FA, per-client access, packages (validated with `dpkg-deb`/`rpm` when installed), the update offer path and rate limits. It runs in CI against a Postgres service.

To do:

- [ ] **Test the Windows agent on real hosts** (Windows 10/11, Server 2019/2022). CI compiles it but nobody has run it. Check the ACL, the Program Files copy, the recovery actions and logging first. Self-update on Windows (service stop/start from the detached watchdog) needs the same.
- [ ] Windows: run jobs and shells inside a Job Object so timeouts and session close kill the whole process tree (Unix jobs use process groups, and Unix shells kill their whole session)
- [ ] MSI installer (WiX) with the server URL and token baked in, like the `.deb`/`.rpm`
- [ ] Persist the agent's job buffer to disk, so results also survive an agent restart (today those jobs become `lost`)

## Phase 3: UI redesign (done)

The dashboard was rebuilt on a design system before the feature phases add their screens. Other RMMs were surveyed first ([docs/research/rmm-ui-survey.md](research/rmm-ui-survey.md)), which added the health model, built-in views, worst-first client health and the agent Activity tab to the plan.

### Decisions (the former open questions)

- **Branding:** no separate product name for now. The company name from Company settings is shown in the sidebar, sign-in page and tab title. Colours are tokens in one file, so per-MSP white-labelling for the PSA portal changes values, not components.
- **Default theme:** follows the OS. Light and dark ship together, with a per-user override saved server-side.
- **Mockups:** designed in code against `/dev/ui`, with no Figma pass.
- **Live updates:** Server-Sent Events rather than a WebSocket. The stream is one-way, so SSE is enough, the browser reconnects it, and it goes through proxies as plain HTTP.

### Done

Design system:

- [x] **Tokens:** CSS variables for colour roles (surface, raised, sunken, border, fg, muted, accent, success, warning, danger, info, chart, syntax, terminal) in `web/src/routes/layout.css`, in light and dark. `static/theme.js` applies the saved theme before first paint.
- [x] **Preferences:** theme, table density, hidden columns, page size, sidebar state and terminal font size, in `users.preferences` (`PUT /api/auth/preferences`).
- [x] **Fonts:** Inter and JetBrains Mono, bundled as same-origin woff2. Vite never inlines them, because the CSP's `font-src 'self'` rejects `data:` URIs.
- [x] **Components** in `src/lib/ui/`: Button, IconButton, Input, Textarea, Select, Combobox, Checkbox, Switch, Field, Tabs, Segmented, Breadcrumbs, PageHeader, Menu, Tooltip, Modal, Drawer, Toaster, ConfirmHost, EmptyState, ErrorState, Skeleton, Spinner, Badge, Kbd, CodeBlock, CopyButton, DataTable and Pagination. Overlays use Bits UI, which handles focus trapping and return, and keyboard navigation. Icons are Lucide.
- [x] **Gallery:** `/dev/ui` shows every component in every state. It exists only in dev builds, or with `VITE_UI_GALLERY=1`.

Layout:

- [x] **Sidebar:** grouped (Overview, Devices, Automation, Admin). It collapses to icons and becomes a drawer below `lg`.
- [x] **Top bar:** client switcher, search, live-update indicator and account menu.
- [x] **Command palette** (Ctrl/⌘ K), backed by a new `GET /api/search`:
  - finds agents (by hostname, OS, IP or signed-in user), clients, sites, scripts and pages;
  - follows the client switcher, with a "search all clients" option;
  - shows recently viewed agents before you type;
  - has actions: run a script on an agent, new script, add client, enroll, theme, shortcuts.
- [x] **Client switcher:** `?client=` in the URL scopes the dashboard, agents, jobs, clients and scripts. Nav links carry it. The Client column turns into Site while a client is selected.
- [x] **Breadcrumbs and page headers:** a standard header with title, count, primary action and overflow menu.

Data:

- [x] **Server paging:** keyset paging and sorting for agents, jobs and the audit log (`crates/rmm-server/src/paging.rs`). Responses are `{items, next, prev, total, total_exact}`; counts stop at 10,000.
- [x] **Agents:** sort by hostname, client, OS, status, health, last seen, enrolled date, CPU, memory, disk or version. Filter by client, site, OS, online, health, enrolled in the last N days, or a search across hostname, IP and user.
- [x] **Jobs:** filter by status, script, client, agent or text.
- [x] **Audit log:** filter by action prefix, user or target.
- [x] **DataTable:**
  - server or local sorting;
  - column visibility and density saved per user;
  - row selection with a bulk-action bar;
  - sticky header, skeleton rows and an empty state;
  - columns that hide on phones;
  - whole-row click.
- [x] **URL state:** every filter, sort, cursor, view and tab is in the URL.
- [x] **Live updates:** `GET /api/events`, one SSE stream per tab.
  - It carries agent online/offline and metrics, and job status and output.
  - Updates are coalesced to at most one per agent or job per second.
  - Events are filtered to the clients the user can see.
  - The session is re-checked every minute, so revocations and access changes take effect.
  - A `resync` event is sent when a browser falls behind.
  - Pages poll instead while the stream is down.
- [x] **Load states:** one helper (`resource()` with `<Async>`) gives skeletons, errors with Retry, and stale-while-revalidate.
- [x] **Toasts and confirmation:**
  - toasts report success and failure, and are announced to screen readers;
  - ConfirmDialog replaces every `confirm()`, and deleting a client, site or agent requires typing its name;
  - the script editor asks before discarding unsaved changes.

Screens:

- [x] **Health model:** healthy, needs attention, unhealthy or no data, computed by the server from:
  - disk at or above 90% (needs attention) or 95% (unhealthy);
  - jobs that failed in the last 24 hours;
  - agent updates that failed or rolled back in the last 7 days.

  It's separate from online/offline, because a workstation that's switched off isn't broken.
- [x] **Dashboard:**
  - attention tiles for offline agents, agents needing attention, failed jobs and full disks, each linking to the filtered list;
  - lists of recently offline agents, failed jobs and the fullest disks;
  - client health sorted worst first;
  - a fleet summary.

  It narrows to one client with the switcher.
- [x] **Agents:** built-in views (All, Online, Offline, Needs attention, New in the last 7 days); bulk Run script and Update; rows update live.
- [x] **Agent detail:**
  - a header with status, health, OS and client › site, and Terminal, Run script and overflow actions;
  - URL tabs: Overview (facts, performance with a 1h/24h/7d/30d range, recent jobs, volumes), Hardware & network, Software (sortable, filterable), Jobs, Activity (new: `GET /api/agents/{id}/activity`) and Terminal.
- [x] **Clients:**
  - a list with health summaries;
  - client detail pages (`GET /api/clients/{id}`) with health tiles, an Agents tab, and a Sites & enrollment tab;
  - rename for clients and sites (`PUT /api/clients/{id}`, `PUT /api/sites/{id}`).
- [x] **Jobs:**
  - live output, fetching only new output via `?since_stdout=&since_stderr=`, with follow-scroll and copy;
  - Rerun from the list and from the job page.
- [x] **Scripts:**
  - a full-page editor (`/scripts/{id}`, `/scripts/new`) on CodeMirror 6, with highlighting for bash/sh, PowerShell and Python;
  - Ctrl/⌘ S saves;
  - the Run dialog takes arguments.
- [x] **Terminal:** fills the page height, with a reconnect banner, a font-size control (saved per user) and full screen.
- [x] **Account:** an Appearance section for theme and density.

Quality:

- [x] **Accessibility:** axe checks every page and the gallery against WCAG 2.2 AA in both themes, in CI. Visible focus rings; status always has a text label; labelled controls; live regions for toasts; 24 px minimum targets; a skip link.
- [x] **Phones:** at 375 px, the agents list stacks status, client and health under the hostname, and navigation is a drawer.
- [x] **Keyboard:** `/` focuses the page's search, `g` + `d/a/c/s/j/l/,` goes to a section, `j`/`k`/Enter/`x` work in lists, and `?` lists the shortcuts.
- [x] **Performance:** xterm and CodeMirror load only on the pages that use them. The first load is about 380 KB of JS before compression.
- [x] **Visual regression:** `web/tests/visual/`, 62 Playwright tests against a mocked API with a frozen clock.
  - Every main page in both themes, phone layouts, the gallery, the palette and ConfirmDialog are screenshotted.
  - Shortcuts and URL state are tested.
  - Baselines are rendered in the Playwright Docker image (`npm run test:visual:docker`), and the CI `visual` job runs in that image.

### Later

- [ ] Undo on cheap actions (toasts already support an action button), and optimistic updates for small toggles.
- [ ] A peek drawer from the agents list, favourites and tags on agents, and agent notes. Tags and notes belong with custom fields in Phase 9.
- [ ] Select every row matching a filter, not just the rows on screen, for bulk actions.
- [ ] Saved views (Phase 9), built on the URL state.
- [ ] Configurable dashboard widgets; script version history.
- [ ] Agent tabs added by later phases: Tickets (7). Phases 4 and 5 added Alerts, Services, Event log and Patches (ten tabs now): move them to a side sub-nav before adding more.

## Phase 4: Monitoring and alerting (done)

- [x] **Alert policies** per client or site, optionally narrowed to one OS: agent offline > N min; CPU, memory or disk held at or above a threshold for M min; service stopped or failed; failed job (any script or one); event log match. Severity (critical / warning / info) feeds the health model: open critical alerts make an agent unhealthy, warnings make it need attention.
  - Offline and threshold policies are evaluated every `RMM_ALERT_EVAL_SECS` (60) with one set-based statement per policy; the others are event-driven as agents report. Offline alerts clear as soon as the agent reconnects, and a restarted server gives agents N minutes to come back before alerting.
  - One unresolved alert per (policy, agent, key): re-checks refresh it, repeated failures and log matches count occurrences. States: open → acknowledged → resolved (cleared, manual, or closed quietly when the policy changes scope, is disabled or deleted).
  - Alerts page (bulk acknowledge/resolve, filters in the URL), alert detail with its deliveries and matched log entries, an Alerts tab per agent, a sidebar badge, and open alerts at the top of the dashboard.
- [x] **Notification channels:** email (SMTP settings under Company settings), generic webhook (optional HMAC-SHA256 signature), Slack incoming webhooks, Teams Workflows webhooks (Adaptive Cards). A Postgres outbox with retries and backoff survives restarts and outages; test sends; a delivery log.
- [x] **Service monitoring:** agents report systemd units / Windows services (state and start mode) when they change; Services tab with start/stop/restart (technicians, audited, names checked against the agent's own list); service alert policies by name, glob, or every automatic service minus exclusions.
- [x] **Event log / journald watchers:** log policies are pushed to the agents they cover (`ServerMsg::Watchers`) and re-pushed when policies change. Linux follows `journalctl -o json`; Windows polls each channel with `wevtutil` by record id. Matching by level, source (unit, syslog identifier, provider), event id and a case-insensitive regex (`regex-lite`, validated on the server). Rate-limited to 20 matches/min per policy on the agent; matches are kept 30 days.
- [x] **Scheduled scripts:** cron expressions (5 fields or `@daily`...) in any IANA time zone, targeting a client, site and/or OS; Run now; a missed run fires once after downtime; agents still busy with the previous run are skipped, so offline machines don't pile up runs; per-schedule output retention (`retain_days`).
- [x] **Metric rollups** instead of TimescaleDB: `agent_metrics_hourly` is upserted every few minutes; raw samples are kept `RMM_METRICS_RAW_DAYS` (7), rollups `RMM_METRICS_RETENTION_DAYS` (now 90); charts beyond 48 hours (and the new 90-day range) read the rollups.

Later:

- [ ] Test the Windows service list/control (PowerShell `Get-CimInstance Win32_Service`) and Event Log watching (`wevtutil`) on real hosts. Both are compile-checked only, like the rest of the Windows agent.
- [ ] Maintenance windows / alert snoozing per agent, and re-notify while an alert stays open.
- [ ] Per-agent policy overrides (exclude one machine from a client-wide policy).
- [ ] macOS: launchd services and the unified log.
- [ ] TimescaleDB (hypertables + continuous aggregates) if Postgres with rollups stops keeping up.
- [ ] Alerts open PSA tickets (Phase 7).

## Phase 5: Patch management (done)

Built as planned, behind a `PatchProvider` trait in `crates/rmm-agent/src/patch/`:

| OS | Scan | Install |
|---|---|---|
| Windows | `IUpdateSearcher` via the Windows Update Agent COM API (`windows` crate); falls back to `PSWindowsUpdate` when the API can't be reached | `IUpdateDownloader` + `IUpdateInstaller`; reports instead of installing when `RebootRequiredBeforeInstallation` |
| Debian/Ubuntu | `apt-get update`, then `apt-get -s dist-upgrade` (stable output, unlike `apt list`); `*-security` suites are security | `apt-get -y install --only-upgrade <pkgs>` with `DEBIAN_FRONTEND=noninteractive`, `--force-confold` |
| RHEL/Fedora | `dnf check-update --refresh` + `dnf updateinfo list --updates` (dnf4 and dnf5 output); `yum` on older systems | `dnf -y upgrade <name.arch…>` |
| Arch | `checkupdates` | `pacman -Syu --noconfirm` (all-or-nothing) |
| macOS | `softwareupdate -l` | `softwareupdate -i`, one at a time |

Done:

- [x] Protocol: `ServerMsg::PatchScan`, `PatchInstall { run_id, ids, reboot_policy }`, `PatchAck`; `AgentMsg::PatchScanResult { updates: [{ id, title, kb, severity, category, size, requires_reboot, version, current_version }], reboot_pending, all_or_nothing, error }`, `PatchProgress`, `PatchResult`. Agents list `capabilities` (`patch`) and their unacknowledged installs (`patch_runs`) in `Auth`, so the server never sends patch messages to older agents and knows which installs are still alive.
- [x] Agent: one scan or install at a time; results are kept and resent after reconnects until acknowledged; a rescan after every install (also gives per-update results for package managers that don't report them); reboot handling (`shutdown -r +1`, `shutdown /r /t 60`); the self-updater waits up to 4 hours for an install to finish. `rmm-agent patches [--install ID…]` for debugging.
- [x] Server: `patches` (per agent and update: state, approval, first seen, failures), `patch_runs` (installs with progress, results and output), `patch_policies` (auto-approve by severity/category, deferral days, automatic install, reboot policy; MSP-wide, per client, per site) and maintenance windows per site (days, start, length, time zone; computed in Postgres). A scheduler asks stale agents to scan, starts automatic installs inside windows, retries failures up to three times and gives up on installs that never report.
- [x] Dashboard: Patches page (updates across the fleet with filters and bulk approve/decline, per-update agent drawer with install now; compliance by client and site; policies and maintenance windows; install history), an install page with per-update results and output, and a Patches tab on agents. Live over the SSE stream.
- [x] Tests: provider parsers against real output, the agent manager with a fake provider, and an end-to-end run (`crates/rmm-server/tests/e2e.rs`) through scan, policy approval, manual approval and decline, install, rescan, compliance, client policies, maintenance windows and an automatic install. The apt and dnf5 providers were also run for real in Debian 12 and Fedora 41 containers, and the pacman scan on Arch.

To do:

- [ ] **Run the Windows provider on real hosts** (with the rest of the Windows agent, Phase 2). It compiles, but nobody has scanned or installed with it yet.
- [ ] Health and alerts: count missing critical updates and pending restarts in agent health, and alert on failed installs (with Phase 4's alert policies).
- [ ] Approval rules that apply to agents that report an update later (today an approval covers the agents that already report it, plus whatever the policy approves).
- [ ] Run package managers in their own systemd scope, so restarting the agent mid-install doesn't kill dpkg.
- [ ] Arch security data (`arch-audit`), Ubuntu Pro/ESM, Windows feature-update targeting, and third-party application patching (winget, Chocolatey).

## Phase 6: Remote desktop (v1 done)

Built as the plan's "simpler v1": frames over the existing agent WebSocket, relayed by the server. Code in `crates/rmm-agent/src/desktop/`, `crates/rmm-server/src/desktop_ws.rs` and `web/src/lib/components/RemoteDesktop.svelte`.

| | Windows | Linux |
|---|---|---|
| Where the helper runs | The service's SYSTEM token moved into the active console session (`WTSGetActiveConsoleSessionId` + `SetTokenInformation(TokenSessionId)` + `CreateProcessAsUserW`), so it can follow input to `Winlogon` (sign-in screen, UAC) with `OpenInputDesktop`/`SetThreadDesktop` | As the owner of the X display in use, found from `DISPLAY`/`XAUTHORITY` in `/proc/*/environ` (a signed-in user over a greeter; ssh-forwarded displays ignored) |
| Capture | GDI `BitBlt` into a DIB, per-monitor DPI aware | MIT-SHM (`0600` segment), else `GetImage`; monitors from RandR 1.5 |
| Input | `SendInput` by scan code, `KEYEVENTF_UNICODE` for typed text; Ctrl+Alt+Del with `SendSAS` from the service (turns on the `SoftwareSASGeneration` policy if it's off) | XTEST by evdev keycode; typed text by keysym, mapping a spare keycode for characters the layout lacks |
| Consent prompt | `WTSSendMessageW` Yes/No | zenity, kdialog or xmessage as the display's user |

Done:

- [x] Protocol (`rmm_proto::desktop`): `DesktopOpen { settings, consent }`, `DesktopSettings`, `DesktopInput`, `DesktopAck`, `DesktopClose`; `DesktopInfo { monitors }`, `DesktopFrame { seq, screen size, picture size, rects, cursor }`, `DesktopClosed { reason }`. Agents advertise the `desktop` capability.
- [x] Helper process (`rmm-agent desktop-helper`, same binary) inside the user's session, talking to the agent over stdin/stdout. A capture crash can't take the agent down, and frame buffers go away with the session. At most 3 sessions per machine.
- [x] Encoding: 64×64 tile diff, one JPEG per run of changed tiles per 64-row band (`jpeg-encoder`, built at `opt-level = 3`). Quality presets: Low (half resolution, q45), Balanced (q65), High (q85). Up to 20 fps while the screen changes, ~8 fps idle.
- [x] Flow control: at most 2 unacknowledged frames; the browser acks each frame after drawing it. The rate adapts to the link and the agent socket stays free for heartbeats. The server drops a session whose browser doesn't keep up instead of blocking the agent's read loop.
- [x] Server: `/api/agents/{id}/desktop` (technician+, Origin check, per-client access, capability check), binary frame format for the browser, input validation, audit (`desktop.open`, `desktop.close` with duration and reason). Per-client consent setting (`PUT /api/clients/{id}/desktop`).
- [x] Dashboard: Remote desktop tab with fit/actual size, full screen with keyboard lock, monitor picker, quality, Ctrl+Alt+Del, type text, consent-waiting state.
- [x] Tests: unit tests (tile diff, keymap, display discovery, framing), the X11 helper against Xvfb (capture, keys, typed Unicode, wheel), and the e2e test drives a session through the real server and agent with a synthetic screen (`RMM_DESKTOP_FAKE`): first full frame, deltas, ack pacing, input, monitor/quality switch, audit, consent declined and allowed.

Decided against for v1:

- **H.264 + WebCodecs** (the plan's encoder): a software `openh264` built from source isn't covered by Cisco's patent licence (only their binary is), and it adds ~1 MB to an agent that's 3 MB. Dirty-rectangle JPEG suits mostly static desktops, decodes everywhere with `createImageBitmap`, and the `Codec` field in each rect leaves room to add H.264 (hardware encoders: Media Foundation pays the royalty on Windows) for video-heavy sessions later.
- **DXGI Desktop Duplication**: GDI first because it works on every desktop, including the secure one, and in RDP sessions, with far less code to get wrong while the Windows agent is untested. DXGI is the faster path to add once it's running on real hosts.

To do:

- [ ] **Run the Windows side on real hosts** (with the rest of the Windows agent). It compiles, but no session has been opened on Windows yet.
- [ ] Wayland: GNOME (`org.gnome.Mutter.RemoteDesktop` + ScreenCast over D-Bus, as gnome-remote-desktop does) and KDE/wlroots via the portal or PipeWire. Today Wayland sessions get a clear error.
- [ ] macOS: ScreenCaptureKit + `CGEvent`, with the Screen Recording and Accessibility permissions.
- [ ] Clipboard sync (text both ways), file drop.
- [ ] H.264 (hardware encoders) for video, DXGI capture on Windows, and WebRTC peer-to-peer with a TURN fallback to take load off the server.
- [ ] Remote cursor shape (XFixes / `GetCursorInfo`); today the local cursor is shown and the remote position is marked.
- [ ] Session recording to object storage; an on-screen "you are being watched" indicator; view-only sessions for the readonly role.

## Phase 7: PSA (professional services automation) (milestones 1-2 done)

### Progress

Done (milestones 1 and 2 of the build order below, so an MSP can run its service desk here and bill elsewhere):

- [x] Contacts per client; client email domains
- [x] Boards with ordered statuses mapped to categories; ticket types; P1-P4 from impact × urgency (or set directly)
- [x] Tickets with `T-10001` numbers, an append-only timeline (replies, notes, field changes, alerts, script results, sessions, merges), assignment, attachments, bulk status/priority/assignee, merge
- [x] Full-text search (trigger-maintained `tsvector` over subject, timeline and contact) in the list and the command palette
- [x] Linked agents with their live state on the ticket; run a script, open a terminal or remote desktop from it (results and sessions recorded on the timeline)
- [x] Object storage: local directory by default, S3/MinIO with a small SigV4 client (`RMM_S3_*`)
- [x] Outbound email: public replies (with attachments) threaded by Message-ID/References and the `[T-n]` tag; assignment notices; acknowledgements
- [x] Inbound email: IMAP polling and a provider webhook (raw MIME, Postmark, Mailgun); threading by tag then In-Reply-To/References; quote stripping; sender → contact → client domain → triage; loop protection (Auto-Submitted, Precedence, X-Autoreply, DSNs, our own addresses, per-sender acknowledgement limit); raw MIME kept for `RMM_EMAIL_RAW_DAYS`
- [x] Alert → ticket per policy (board, priority), deduplicated per alert/agent, notes on clear, auto-resolve if untouched, reopen on return, stop auto-resolving after 3 reopens
- [x] Resolved tickets close after `RMM_TICKET_CLOSE_DAYS`

Left over from milestones 1-2:

- [ ] Microsoft Graph mailboxes (subscriptions) or IMAP with XOAUTH2. Basic-auth IMAP is off in Microsoft 365, so M365 tenants currently have to forward to a webhook mailbox
- [ ] Teams for assignment (only users today), split a reply into a new ticket, canned responses and macros, CSAT survey
- [ ] Per-board notification of new tickets through the notification channels
- [ ] Attachments over 8 MB (the global request body limit)

### Review notes (2026-11)

Decisions and corrections made while building milestones 1-2:

- **Permissions model:** not needed until time and billing (rates must be hidden from some technicians). Tickets use the existing roles: read-only users read, technicians work tickets, admins configure boards and mailboxes. Do the permission sets before milestone 5, not before milestone 1.
- **Object storage:** a hard MinIO dependency is heavy for small installs. Local directory is the default; S3 is opt-in. Session recordings (Phase 6) can use the same `Storage`.
- **Priorities:** a `priorities` table added nothing; priority is 1-4 on the ticket with impact × urgency (1-3 each) computed in code. SLA targets will key on the number.
- **Search:** a generated `tsvector` column can't read other tables (timeline, contact), so triggers maintain it.
- **Triage:** unknown senders' tickets have no client. The existing scope filter (`client_id = ANY(scope)`) already hides them from scoped users, so triage needs no extra access rules.
- **Alert dedupe:** keyed on the alert's (policy, agent, key), not the alert row, so a flapping check reopens one ticket instead of opening many. "Untouched" is `touched_at IS NULL`, set by any person's action.
- **Email identity:** contacts are matched on `From`, never `Reply-To` (anyone can set that). An address used by two clients' contacts goes to triage rather than guessing.
- **Open questions answered:** multi-currency: store a currency per client (company default), decide before the invoice tables. Retention: raw MIME is pruned after `RMM_EMAIL_RAW_DAYS`; per-client purge of closed tickets (GDPR) is still open. Co-managed IT: works today through `user_clients` (a technician limited to one client sees only its tickets).

The goal is a built-in PSA, so an MSP can run its service desk, contracts and billing in the same product as the RMM. The selling point is the link between the two: alerts open tickets, tickets show the device's live state, and invoices count the enrolled agents. A ticket tracker sitting next to the RMM wouldn't offer that.

Out of scope: general ledger, accounts payable, payroll and tax filing. Finalised invoices sync to QuickBooks Online or Xero, which handle those. We won't do payment processing either; at most an optional Stripe payment link on each invoice.

### Prerequisites

- **Per-client access control** (done in Phase 2: `user_clients`, scoped queries). Every PSA query is scoped by client. The client-portal role was deferred to here: it's the contacts auth below, and portal users must never reach technician endpoints.
- **Notification channels and outbound email** (Phase 4, done). Ticket replies, SLA warnings and invoice delivery all go through them.
- **Alert policies** (Phase 4, done). Alerts are the main automatic source of tickets.
- **A permissions model instead of the `role` enum.** The PSA needs finer roles: dispatcher, billing, and a technician who can log time but can't see rates or invoices. Move to named permission sets (`tickets.write`, `billing.read`, `contracts.manage`, ...) assigned to roles. Keep `admin`/`technician`/`readonly` as built-in sets.
- **Object storage** (S3-compatible, MinIO in the deploy stack) for ticket attachments and invoice PDFs. Session recordings in Phase 6 need it too.

### Data model

New tables. All of them hang off `clients` (and optionally `sites`/`agents`), so tenancy and access control carry over.

| Area | Tables | Notes |
|---|---|---|
| Contacts | `contacts` | People at a client (name, email, phone, site, `is_primary`, `portal_enabled`). Separate from `users`: contacts are customers, users are MSP staff. |
| Portal auth | `contact_sessions`, `contact_credentials` | Separate from `user_sessions` so a portal cookie can never authenticate against the technician API. Magic-link sign-in by default; password plus TOTP optional. |
| Tickets | `tickets`, `ticket_events`, `ticket_attachments`, `ticket_agents` | Human ticket number from a sequence (`T-10423`). `ticket_events` is an append-only timeline: public reply, internal note, status change, assignment, time entry, script run, merge. Many-to-many link to agents. |
| Queues | `boards`, `board_statuses`, `ticket_types` | Boards such as Service Desk, Projects or Alerts. Each has an ordered set of statuses, each mapped to a category (`new`, `open`, `waiting_client`, `waiting_vendor`, `resolved`, `closed`), which drives SLA pausing and reporting. |
| Priority | `priorities` | Impact × urgency matrix that resolves to P1–P4. |
| SLA | `sla_policies`, `sla_targets`, `business_calendars`, `holidays` | Response, first-update and resolution targets per priority. Business hours per calendar, with timezone. A client's contract chooses its policy. |
| Time | `time_entries`, `work_types`, `work_roles` | Start/end or a duration. Each entry has a billable flag, a work type (remote, onsite, after-hours), the technician and the ticket or project. `invoice_line_id` is set once billed, which locks the entry. |
| Contracts | `contracts`, `contract_items`, `contract_rate_overrides` | Agreement types: managed per device, managed per user, block hours (prepaid bank), time and materials, and flat recurring. Each has a start/end date and a billing cycle, and covers some work types (in scope vs. billable on top). |
| Catalog | `products` | Recurring and one-off items (licences, hardware, labour SKUs), with cost and price. |
| Billing | `invoices`, `invoice_lines`, `invoice_number_seq` | Lifecycle: draft → finalised → sent → paid/void. A finalised invoice is immutable and numbered without gaps; corrections are credit notes. Money is `bigint` minor units plus an ISO currency code, never floats. |
| Knowledge | `kb_articles`, `client_docs` | KB articles, internal or public in the portal. Per-client documentation pages (network layout, vendors, procedures). |
| Scheduling | `schedule_entries` | A technician, a time range, and a link to a ticket or project. |
| Projects | `projects`, `project_phases`, `project_tasks` | Budgeted hours with burn-down; tasks can spawn tickets. Comes last (see the build order). |

Search uses Postgres full text: a generated `tsvector` over ticket subject, events and contact name, with a GIN index. That's enough until the data is very large.

### Ticket intake

- **Dashboard and portal:** forms, with ticket type and priority. The portal form can ask type-specific questions.
- **Email-to-ticket:** one or more support mailboxes per company. There are three ways to receive mail: IMAP IDLE/poll, Microsoft Graph subscriptions for M365 mailboxes (the common case for MSPs), or an inbound webhook from Postmark, SES or Mailgun.
  - Threading: match on the `[T-10423]` subject tag first, then `In-Reply-To`/`References` against the `Message-ID`s we sent. Otherwise open a new ticket.
  - Sender → contact → client: match the exact address first, then the client's email domains. Unknown senders go to a triage queue; don't auto-create contacts.
  - Loop protection: ignore `Auto-Submitted: auto-*`, `Precedence: bulk/junk/list` and bounces (DSNs). Rate-limit auto-replies per sender. Never auto-reply to our own mailboxes.
  - Strip quoted reply text when storing an event, but keep the raw MIME in object storage.
- **Alerts (the RMM link):** an alert policy can open a ticket on a chosen board and priority.
  - Deduplicate: while the same alert on the same agent has an open ticket, add an event to it instead of opening a new one.
  - When the alert clears, add a note. Optionally auto-resolve the ticket if nobody has touched it.
  - Flap protection: count the reopens and stop auto-resolving after N.
- **API and webhooks:** with the public API (Phase 9). Lets monitoring tools and forms outside the RMM create tickets.

### Working a ticket

- The ticket page has a sidebar with the linked agents' live status, last metrics, recent alerts and patch status. From there a technician can:
  - run a library script, with the job output attached to the timeline as an internal note;
  - open a web terminal (or remote desktop, Phase 6), with session start/end recorded as an event and a time entry suggested from the duration.
- **Timer:** start/stop on the ticket. Logging time asks for the work type and billable flag and, optionally, writes the note as a public reply.
- **Assignment and dispatch:** assign to a technician or a team. The dispatcher's calendar view lets them drag tickets onto technicians' schedules. Two-way sync with M365 and Google calendars comes later.
- **Bulk actions:** merge duplicates, split a reply into a new ticket, and change status, assignee or priority in bulk.
- **Canned responses and macros:** set status, add a note, assign. Templates have variables (`{{contact.first_name}}`, `{{ticket.number}}`).
- **Satisfaction survey:** sent on close, one click, with optional feedback. Results feed reporting.

### SLA engine

- When a ticket is created, or its priority or contract changes, compute `respond_by`, `update_by` and `resolve_by`. Use the contract's SLA policy and its business calendar in the client's timezone, minus holidays.
- Store these deadlines on the ticket so list views can sort and filter without recomputing.
- Statuses in the `waiting_client` category pause the clock. Store the accumulated paused time so the deadlines shift without extra bookkeeping.
- A background task (alongside the existing job-lifecycle sweeper) sends warnings at 75% and on breach through the notification channels. It records `sla_breached_at` so attainment reporting is cheap.
- First response counts only on a public reply by a technician. Internal notes and automated messages don't count.

### Time, contracts and billing

- **Rate lookup**, first match wins: contract rate override for the work type → work-role rate → work-type default → technician default.
- **Contract coverage:** per-device and per-user agreements cover their in-scope work types at no extra charge, and anything else becomes billable. Block-hours contracts draw down the bank and bill any overage at the overage rate. A low-balance warning goes to the account manager.
- **Device counts come from the RMM:** per-device contracts bill on the number of agents enrolled under the client on the cycle date, optionally filtered by OS (workstation vs. server pricing). Snapshot the count onto the invoice line so later enrolments don't change a finalised invoice.
  - Per-user contracts use a manually entered count. M365 licence counts via Graph could feed it later.
- **Time approval:** technicians submit timesheets weekly and a manager approves them. Only approved, billable entries that no contract covers reach an invoice.
- **Invoice run** (monthly, or per contract cycle) generates drafts per client:
  - recurring contract lines, prorated for mid-cycle starts;
  - device and user counts;
  - uncovered billable time;
  - products sold on tickets.
  - A person reviews and edits the drafts, then finalises: numbering, PDF and email to the client's billing contact. Every billing change goes in `audit_log`.
- **Accounting sync:** push finalised invoices, customers and items to QuickBooks Online or Xero over OAuth. Pull payment status back. Tax comes from the accounting system's tax codes; we don't calculate it ourselves.

### Client portal

A separate route group (`/portal`) with its own layout and branding (company name and logo from Company settings). Contacts can:

- view and reply to their tickets, open new ones and upload attachments;
- see a read-only status list of their client's devices (online, last seen, patch compliance). Off by default, enabled per client;
- read public KB articles;
- if they're a billing contact: see invoices and their PDFs, and the payment link if one is configured.

Portal access is scoped to one client in the session and checked on every query. This depends on the per-client access work in Phase 2.

### Documentation and credentials

Per-client documentation pages are straightforward. A **password vault** is a separate, larger decision: it would hold the most sensitive data in the product. If we build one:

- envelope encryption: a per-client data key wrapped by a key that isn't in Postgres (KMS, or a key file mounted only on the server);
- reveal on request with a mandatory audit entry;
- a permission of its own;
- 2FA required to view.

Do this before the vault, and before anything else secret is stored: encrypt the TOTP secrets at rest with the same scheme. Today they're plaintext in Postgres.

### Reporting

- Service desk: tickets opened and closed per client, board and technician; backlog age; first-response and resolution times; SLA attainment; CSAT.
- Utilisation: billable hours vs. logged hours vs. available hours per technician.
- Client profitability: invoiced revenue against time cost (hours × a loaded cost rate per technician) plus product cost.
- Quarterly business review (QBR) PDF per client, combining PSA and RMM data: ticket trends, top issues, SLA attainment, device count, patch compliance, alerts and uptime.

### Web UI

Built on the Phase 3 components, under the sidebar's Service desk group. New top-level sections: **Tickets** (board/list views, saved filters), **Schedule**, **Contacts** (or a tab under Clients), **Contracts**, **Billing** and **Knowledge**. Client and agent pages get Tickets tabs. Settings gets boards and statuses, SLA policies and calendars, work types and rates, the product catalog, mailboxes, and accounting integration.

### Suggested build order

1. **Ticketing core:** contacts, tickets, timeline, boards/statuses/priorities, assignment, attachments, search, and agent links with the live-status sidebar.
2. **Email and alerts:** outbound replies and notifications; inbound email-to-ticket with threading and loop protection; alert → ticket with dedupe and auto-resolve.
3. **Client portal:** separate auth, tickets, KB.
4. **SLA:** policies, business calendars, deadline computation, pause, warnings and breaches.
5. **Time and contracts:** timer, time entries, work types and rates, contract types and coverage rules, timesheet approval.
6. **Billing:** invoice runs, finalisation, PDFs, QuickBooks Online/Xero sync.
7. **Scheduling, projects, documentation, reporting, QBRs.** The vault, if we build one, comes last and gets its own security review.

Each milestone should be usable by itself. After step 2, an MSP can already run its service desk here and bill from another system.

### Open questions

- **Build vs. integrate.** Many MSPs already use HaloPSA, ConnectWise Manage or Autotask and won't switch. Keep a sync integration (Phase 9) for them alongside the built-in PSA: alerts → their tickets, and agents → their configurations.
- **Multi-currency:** one currency per company is simpler; one per client is what MSPs billing across borders need. Pick one before creating the invoice tables.
- **Retention:** how long to keep raw email MIME and attachments, and whether closed tickets can be purged per client (GDPR requests from a client's contacts).
- **Who works the tickets:** if a client's own IT staff (co-managed IT) need to work tickets, they need technician-like access limited to one client. This is the same `user_clients` work from Phase 2.

## Phase 8: Endpoint protection (EDR / AV) (planned)

Goal: endpoint protection managed from the same console, so a detection becomes an alert, a ticket and a response action next to the device's live state. MSPs pay per seat for this today, and cyber insurers ask for it.

This is the largest phase on the roadmap. Detection quality decides whether it is any good, and that takes years of tuning against false positives, not just sensor code. The milestones are ordered so each one is useful alone and the riskiest work (blocking, kernel code) comes last.

### Scope decisions

- **Manage the built-in protection first.** Microsoft Defender (Windows), ClamAV (Linux) and XProtect (macOS) already scan files. Reporting their state, triggering scans and turning findings into alerts is the cheapest useful step.
- **Run beside Defender, not instead of it.** Replacing Defender as the registered antivirus in Windows Security Center needs Microsoft Virus Initiative membership and an ELAM driver, which in practice needs an established product with independent test results. Until then we add telemetry, detection and response on top of Defender.
- **User mode before kernel mode.** Prefer the platform's supported telemetry APIs (ETW on Windows, eBPF/fanotify/audit on Linux, Endpoint Security on macOS). A custom kernel driver is a last step, only if the gaps prove to matter, because a driver fault can crash every machine it is on.
- **Not a managed detection service.** Software can't watch the console overnight. We provide the queue, context and response buttons; staffing or an MDR partner is the MSP's call.
- **No machine-learning classifier early.** It needs a labelled corpus and continual retraining. Start with hashes, signatures, YARA-style rules and behaviour rules.

### Prerequisites

- Windows agent proven on real hosts (Phase 2 to-do).
- Permission sets from Phase 7: `security.read`, `security.respond` (quarantine, isolate), `security.manage` (policies, exclusions).
- Signed content pipeline: rule and signature bundles signed like agent releases (`rmm-sign`), verified on the agent, rolled out in stages.
- Agent job buffer persisted to disk, so response actions survive a restart.
- Secrets encrypted at rest (Phase 7 vault notes). Telemetry includes command lines, which can contain credentials.

### Architecture

- **Separate sensor process** (`rmm-sensor`), supervised by the agent, so a sensor fault can't take down remote access and it can be switched off per client. Local IPC to the agent, which forwards over the existing socket.
- **Events stay on the machine by default.** Keep a local, size-limited event store and send only detections and summaries. Pull detailed history on demand during an investigation.
- **Server side:** `security_detections` (rule, severity, process and file context, state), `security_policies` (per client/site/OS, like alert and patch policies), `security_exclusions`, `quarantine_items`, `content_versions`. Detections feed the health model and open alerts; alerts already open tickets (Phase 7).
- **Tamper resistance for our own product:** protect the agent's files and service from non-admin users, report when the sensor stops, and alert on it.

### Milestones

1. **Protection status and management.** Read Defender, ClamAV and XProtect state (enabled, signature age, last scan, active threats). Start scans and signature updates from the console. Alert on disabled protection, stale signatures and detections. Show a Security tab per agent and a fleet view.
2. **File scanning.** On-demand and scheduled scans in the sensor with hash reputation and rule matching against a signed bundle. Quarantine with restore (files moved to a protected store, never deleted outright). Exclusions with an audit trail.
3. **Telemetry.** Process start, command line, parent chain, module loads, network connections, and file and registry changes of interest, from the supported platform APIs above. Local store and an on-demand query from the console.
4. **Behaviour detection.** A rule engine over the telemetry (rule format, severity, MITRE ATT&CK tags), with a starter set for common ransomware, credential-theft and persistence behaviour. Every rule ships with test cases and a measured false-positive rate on a clean-fleet baseline; new rules start in audit-only mode.
5. **Response.** Kill a process tree, quarantine a file, isolate a host from the network while keeping the management channel, collect a triage package, and roll back changes where feasible. All audited and permission-gated, available from alerts and tickets.
6. **Investigation UI.** Detection detail with a process tree and timeline, search across the fleet, and "have we seen this hash elsewhere".
7. **Prevention.** Block-on-detect for high-confidence rules only, after enough audit-mode history. Staged rollout (canary clients first) with automatic rollback if a content update raises crash or false-positive counts.
8. **Later or never:** custom kernel driver, ELAM and MVI registration, a cloud sandbox, threat-intel feed integration, ML classification, application control and device control.

### Testing

- Unit tests per rule against recorded event streams, and a replay harness so rules run in CI.
- Benign-software corpus run before every content release to catch false positives.
- Detection coverage checked against a published adversary-emulation test set in an isolated lab, never on customer machines.
- Performance budget: CPU, memory and disk I/O caps for the sensor, measured on low-end hardware.
- Content and agent updates tested for safe rollback; a bad rule must be disableable from the server without a new agent build.

### Risks and open questions

- **False positives and outages.** A bad rule or update can quarantine legitimate software fleet-wide. Staged rollout, audit-first and a kill switch are required before any blocking.
- **Liability and expectations.** Selling protection implies a promise. Marketing and contracts need to say what it does and doesn't cover.
- **Maintenance cost.** Rule upkeep never ends; decide up front whether to license a signature/threat-intel feed or maintain our own.
- **Windows first, Linux second, macOS last** matches where MSP fleets are, but macOS needs Apple entitlements and notarisation.
- **Build vs. integrate.** Some MSPs already standardise on another EDR. Keep an integration path (ingest their detections as alerts) as a parallel option.

## Phase 9: Nice to have

- File browser and transfer (upload/download over the agent socket in chunks)
- Process list / kill and a services panel
- Software deployment (winget / choco / apt packages, MSI push)
- Asset warranty lookups, custom fields, tagging, saved agent filters
- External PSA integrations (HaloPSA, ConnectWise Manage, Autotask) for MSPs not using the built-in one (Phase 7), API keys for automation, a public REST API with OpenAPI docs
- Horizontal scaling: route hub messages over Postgres LISTEN/NOTIFY or NATS so several server nodes can share agents
