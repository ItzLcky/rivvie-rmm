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

## Phase 3: UI redesign

Do this before the feature phases. The dashboard is still small (about 1,200 lines over 14 pages), so redoing it is cheap now. Every phase after this one adds screens, and the PSA alone adds six top-level sections. They should be built on the new components rather than redone later.

### What's wrong today

- Styling is Tailwind classes with hard-coded `slate`/`sky` colours, plus a few shared classes in `layout.css`. There are no design tokens, and only a dark theme.
- Inter and JetBrains Mono are in the font stack but never loaded, so everyone gets the system font.
- Destructive actions use the browser's `confirm()`. Some load failures are swallowed: if `/dashboard` fails, the page stays blank. Nothing shows a loading state.
- The sidebar is a fixed 224 px, with no layout for narrow screens.
- `Modal` doesn't trap focus or return it when it closes.
- Every list page polls the API every 10–15 s.
- Tables have no sorting, paging or column choice. The agents list fetches every agent.
- Some filters are read from the URL but never written back to it, so a filtered view can't be bookmarked or shared.

### Design system

- **Tokens:** CSS variables in `@theme` for colour roles: surface, raised, border, text, muted, accent, success, warning, danger, info. Define a light and a dark theme. Default to the OS setting, with an override saved per user on the Account page.
- **Fonts:** self-host them as woff2 files under `static/`, so they keep working under the strict CSP from Phase 2. Or drop them and use the system stack.
- **Components** in `src/lib/ui/`:
  - controls: Button, IconButton, Input, Select, Combobox (searchable, for client/site/agent pickers), Checkbox, Switch;
  - navigation and overlays: Tabs, Breadcrumbs, PageHeader, Dropdown menu, Tooltip, Modal, Drawer;
  - feedback: Toast, ConfirmDialog (big deletes make you type the name), EmptyState, Skeleton, Badge;
  - data: DataTable, Pagination.
- **Headless primitives:** build menus, comboboxes, dialogs and tooltips on Bits UI (headless, written for Svelte 5), so focus and keyboard handling are right. Style them with our tokens.
- **Icons:** Lucide (`@lucide/svelte`), replacing text glyphs such as `✕`.
- **Component gallery:** a `/dev/ui` route, in dev builds only, that shows every component in every state in both themes. Cheaper than Storybook.

### Navigation and layout

- **Grouped sidebar:**
  - Overview: Dashboard
  - Devices: Agents, Clients & Sites
  - Automation: Scripts, Jobs, later Schedules and Patches
  - Alerts (Phase 4)
  - Service desk (Phase 7)
  - Admin: Audit log, Company settings

  It collapses to icons, and becomes a drawer on screens narrower than `lg`.
- **Command palette** (Ctrl+K) in a top bar. It jumps to any agent, client, script or ticket and runs actions ("Run script on…", "New ticket"). Needs a server `/search` endpoint.
- **Client switcher:** pick a client to scope every list. Keep the choice in the URL (`?client=`) so links carry it. This matches the per-client access control in Phase 2.
- **Breadcrumbs** on detail pages: Client › Site › Agent.
- **Standard page header:** title, item count, the primary action, and secondary actions in an overflow menu.

### Data and feedback

- **DataTable:**
  - sorting and paging done on the server, with keyset pagination (agent and job tables keep growing);
  - column visibility saved per user;
  - row selection with a bulk-action bar;
  - sticky header, and a compact/comfortable density toggle.
- **URL state:** every filter and sort goes in the URL, so views can be bookmarked and shared. Saved views (Phase 8) build on this.
- **Live updates:** replace per-page polling with a single WebSocket (or SSE stream) for the dashboard. The server pushes agents going online/offline, new metrics and job status changes; pages subscribe to what they show. The hub already sees these events. Fall back to polling if the socket drops.
- **Load states:** every fetch shows a skeleton while loading, plus empty and error states with a retry button. Put this in one shared load helper instead of repeating it on each page.
- **Feedback:** toasts report whether actions succeeded. ConfirmDialog replaces `confirm()`. Offer undo where it's cheap; small toggles update optimistically.

### Key screens

- **Dashboard:** lead with what needs attention: offline agents, failed jobs and full disks; later, alerts, patch compliance and SLA breaches. Add a health grid per client. Configurable widgets can wait until after v1.
- **Agent detail:**
  - a header with status, OS, client/site and quick actions (terminal, run script, later reboot);
  - tabs: Overview, Inventory, Software, Jobs and Terminal, later Patches, Alerts and Tickets;
  - charts with a time-range picker.
- **Clients & Sites:** a client list with a health summary (agents online/total, later alerts). Each client gets a detail page with its sites, agents and enrolment tokens, and later its contracts and tickets. Today all of this is on one page.
- **Jobs:** stream output live on the job page, filter by status, script and client, and rerun failed jobs.
- **Script editor:** CodeMirror 6 with syntax highlighting per interpreter, and a form for arguments. Version history later.
- **Terminal:** full height, with a reconnect banner and a font-size control.

### Quality bar

- **Accessibility:** WCAG 2.2 AA:
  - everything reachable by keyboard, with visible focus rings;
  - contrast checked in both themes;
  - status never shown by colour alone (`Status` already has a text label; keep it that way);
  - labelled form controls, and `aria-live` for toasts.
- **Phones:** triage should work on a 375 px screen: check status, read and acknowledge alerts, run a script. Full editing can stay desktop-only.
- **Keyboard shortcuts:** `/` focuses search, `g a` goes to agents, `j`/`k` move through lists, and `?` lists the shortcuts.
- **Performance:** lazy-load heavy dependencies (xterm, charts, CodeMirror) on the pages that use them, so the first load stays small.
- **Visual regression:** Playwright screenshots of `/dev/ui` and the main pages in both themes. Run them in CI next to the Phase 2 integration tests.

### Build order

1. Tokens, themes, fonts, icons, the core components and `/dev/ui`.
2. The new layout: grouped sidebar, mobile drawer, top bar, breadcrumbs, and the command palette with its search endpoint.
3. DataTable with URL state and server-side paging. Move Agents, Jobs and the Audit log to it.
4. Loading, error, toast and confirm patterns on every page.
5. Live updates over the single socket.
6. The reworked Dashboard, Agent detail and Clients pages (Clients split into detail pages).

Each step ships separately. Old and new pages can run side by side, because pages adopt the new components one at a time.

### Open questions

- **Branding:** does the product get its own name and logo, beyond the company name shown today? The PSA client portal will want per-MSP white-labelling, which the tokens make easy.
- **Default theme:** light or dark?
- **Mockups first?** A design pass in Figma before step 1, or design directly in code against `/dev/ui`.

## Phase 4: Monitoring and alerting

- [ ] Alert policies per client or site: offline > N min, CPU/mem/disk thresholds held for M min, service stopped, failed job
- [ ] Notification channels: email (SMTP), webhook, Slack/Teams
- [ ] Service monitoring: systemd units / Windows services. Inventory them, alert on state, start/stop/restart from the UI.
- [ ] Event log / journald watchers with match rules
- [ ] Scheduled scripts (cron-style) per client or site, with output retention
- [ ] Move `agent_metrics` to TimescaleDB, or add hourly rollups, once fleets reach thousands of agents

## Phase 5: Patch management

Agent side, behind a `PatchProvider` trait:

| OS | Scan | Install |
|---|---|---|
| Windows | `IUpdateSearcher` via the Windows Update Agent COM API (`windows` crate); fall back to `PSWindowsUpdate` | `IUpdateInstaller`; reboot handling via `IUpdateInstaller::RebootRequiredBeforeInstallation` |
| Debian/Ubuntu | `apt-get -s upgrade` / `apt list --upgradable` (after `apt-get update`) | `apt-get -y install --only-upgrade <pkgs>` with `DEBIAN_FRONTEND=noninteractive` |
| RHEL/Fedora | `dnf check-update --refresh` / `dnf updateinfo list --sec` | `dnf -y upgrade <pkgs>` |
| Arch | `checkupdates` | `pacman -Syu --noconfirm` (all-or-nothing) |
| macOS | `softwareupdate -l` | `softwareupdate -i` |

Protocol: `ServerMsg::PatchScan`, `PatchInstall { ids, reboot_policy }` → `AgentMsg::PatchScanResult { updates: [{ id, title, kb, severity, size, requires_reboot }] }`, `PatchProgress`, `PatchResult`.

Server: `patches` table (per agent and update), patch policies (auto-approve by severity/category, deferral days, maintenance window per site, reboot policy), approval UI, compliance dashboard (% patched per client).

## Phase 6: Remote desktop

The hardest piece. Plan:

1. **Capture** (agent, a separate `rmm-desktop` helper process):
   - Windows: DXGI Desktop Duplication. The agent runs as SYSTEM in session 0, so it must launch the helper *into the active console session* (`WTSGetActiveConsoleSessionId` + `WTSQueryUserToken` + `CreateProcessAsUserW`) to see the desktop, the UAC secure desktop, and the login screen.
   - Linux: PipeWire screencast portal (Wayland) or XShm (X11).
   - macOS: ScreenCaptureKit (needs the Screen Recording TCC permission).
2. **Encode:** H.264 via hardware encoders (Media Foundation / VA-API / VideoToolbox) with an `openh264` software fallback. Send only changed frames, with an adaptive bitrate.
3. **Transport:** WebRTC (the `webrtc-rs` crate) so video goes peer-to-peer when possible, with the server as signalling and a TURN relay fallback. Simpler v1: send encoded frames over the existing WebSocket, relayed by the server, and decode in the browser with WebCodecs (`VideoDecoder`).
4. **Input:** `SendInput` (Windows), `uinput` or XTest (Linux), `CGEvent` (macOS). Map browser keyboard and mouse events, including a Ctrl+Alt+Del button (`SendSAS` on Windows).
5. **Extras:** clipboard sync, multi-monitor selection, an end-user consent prompt option per client, session recording to object storage.

An interim option is to bundle an existing RustDesk server/client and broker sessions from the dashboard. That's useful for early customers while native remote desktop gets built.

## Phase 7: PSA (professional services automation)

The goal is a built-in PSA, so an MSP can run its service desk, contracts and billing in the same product as the RMM. The selling point is the link between the two: alerts open tickets, tickets show the device's live state, and invoices count the enrolled agents. A ticket tracker sitting next to the RMM wouldn't offer that.

Out of scope: general ledger, accounts payable, payroll and tax filing. Finalised invoices sync to QuickBooks Online or Xero, which handle those. We won't do payment processing either; at most an optional Stripe payment link on each invoice.

### Prerequisites

- **Per-client access control** (done in Phase 2: `user_clients`, scoped queries). Every PSA query is scoped by client. The client-portal role was deferred to here: it's the contacts auth below, and portal users must never reach technician endpoints.
- **Notification channels and outbound email** (Phase 4). Ticket replies, SLA warnings and invoice delivery all go through them.
- **Alert policies** (Phase 4). Alerts are the main automatic source of tickets.
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
- **API and webhooks:** with the public API (Phase 8). Lets monitoring tools and forms outside the RMM create tickets.

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

- **Build vs. integrate.** Many MSPs already use HaloPSA, ConnectWise Manage or Autotask and won't switch. Keep a sync integration (Phase 8) for them alongside the built-in PSA: alerts → their tickets, and agents → their configurations.
- **Multi-currency:** one currency per company is simpler; one per client is what MSPs billing across borders need. Pick one before creating the invoice tables.
- **Retention:** how long to keep raw email MIME and attachments, and whether closed tickets can be purged per client (GDPR requests from a client's contacts).
- **Who works the tickets:** if a client's own IT staff (co-managed IT) need to work tickets, they need technician-like access limited to one client. This is the same `user_clients` work from Phase 2.

## Phase 8: Nice to have

- File browser and transfer (upload/download over the agent socket in chunks)
- Process list / kill and a services panel
- Software deployment (winget / choco / apt packages, MSI push)
- Asset warranty lookups, custom fields, tagging, saved agent filters
- External PSA integrations (HaloPSA, ConnectWise Manage, Autotask) for MSPs not using the built-in one (Phase 7), API keys for automation, a public REST API with OpenAPI docs
- Horizontal scaling: route hub messages over Postgres LISTEN/NOTIFY or NATS so several server nodes can share agents
