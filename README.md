# RMM

A self-hosted, multi-tenant remote monitoring and management platform for MSPs.
The agent and server are written in Rust; the dashboard is a SvelteKit SPA.

| Platform | Status |
|---|---|
| Linux agent | Working: inventory, metrics, scripts, terminal, systemd service, service monitoring and control, journald watchers, remote desktop (X11 sessions) |
| Windows agent | Code complete, compile-checked in CI only (registry inventory, PowerShell/cmd, ConPTY, Windows service, service monitoring, Event Log watchers, remote desktop). Needs testing on a real host. |
| macOS agent | Builds; metrics and scripts work. No launchd install or software inventory yet. |

The release agent (Linux x86_64) is a **3.7 MB** single binary that idles at **~10 MB RSS** with 3 threads (plus a `journalctl` child while log watchers are set, and a helper process per open remote desktop session).

## Layout

```
crates/
  rmm-proto/    Wire protocol shared by agent and server (MessagePack over WebSocket)
  rmm-agent/    Endpoint agent: collector, script runner, PTY shell, remote desktop, service install, self-update
  rmm-server/   axum server: agent hub, REST API, terminal and desktop relay, serves the dashboard
    migrations/ Postgres schema (applied automatically on start)
    tests/      End-to-end test: real server, Postgres and agent processes
  rmm-sign/     Offline release signing for agent self-update (never deployed to the server)
  rmm-loadgen/  Load generator: simulated agents (the real protocol), dashboards and API users
web/            SvelteKit dashboard (static SPA, served by rmm-server)
deploy/         Dockerfile, docker-compose (Postgres + server + Caddy), Caddyfile
docs/           Roadmap and design notes
```

## How it works

```
 ┌───────────┐   wss://…/api/agent/ws (1 socket per agent,   ┌──────────────┐      ┌──────────┐
 │ rmm-agent │ ◄──────────── MessagePack frames) ──────────► │  rmm-server  │ ───► │ Postgres │
 └───────────┘                                               │  (axum)      │      └──────────┘
                    https://…/api/*  (REST, cookie auth)     │              │
 ┌───────────┐ ◄───────────────────────────────────────────► │  agent hub   │
 │  browser  │   wss://…/api/agents/{id}/shell|desktop       │  relays      │
 └───────────┘ ◄───────────────────────────────────────────► └──────────────┘
```

- **Tenancy:** clients → sites → agents. Enrollment tokens are scoped to a site, so an agent lands in the right client automatically.
- **Enrollment:** `rmm-agent enroll --server URL --token T` swaps a time- and use-limited token for a permanent per-agent secret. The server stores only a SHA-256 of it. Re-enrolling a machine that still has its config keeps its agent record (the agent proves it holds the old secret); a token alone always creates a new record, so a leaked token can't take over existing agents. The agent refuses plain `http://` servers other than localhost unless you pass `--insecure`.
- **Transport:** the agent dials out, so endpoints need no inbound ports. Everything is multiplexed over one WebSocket: heartbeats (every 30 s), inventory (every 6 h or on demand), script jobs, and PTY streams. The agent reconnects with jittered exponential backoff, and treats 100 s of silence from the server as a dead connection.
- **Jobs:** sending a script to an offline agent queues it, and it runs on reconnect (queued jobs expire after `RMM_JOB_QUEUE_DAYS`). Output streams into Postgres (capped at 1 MB per stream). Jobs outlive the connection: the agent keeps a copy of each job's output and its result, and resends them after a reconnect or server restart until the server acknowledges them. The agent also keeps each job on disk (`job-results` in its state directory) until the server acknowledges it, so results survive an agent restart, crash or self-update too; a job that was still running when the agent stopped is reported as `error` with the output it had produced. A job is only marked `lost` when the agent comes back with no record of it (its state was wiped) or never comes back. Timeouts kill the whole process tree (a process group on Unix, a Job Object on Windows), and closing a terminal kills everything started from it.
- **Terminal:** xterm.js ↔ server relay ↔ PTY on the agent (bash/zsh on Linux, PowerShell through ConPTY on Windows).
- **Remote desktop:** view and control the machine's screen from the browser, relayed over the agent's existing socket (no extra ports). Changed areas are sent as JPEG, paced by the browser so slow links get fewer frames rather than lag. An optional consent prompt, and whether remote desktop, the terminal and file access are allowed at all, come from the device's policy set. See [Remote desktop](#remote-desktop).
- **Per-client access:** admins see every client. Technicians and read-only users see every client by default, or only the clients an admin picks under Company settings → Users. Everything they can reach (agents, sites, tokens, jobs, terminal, dashboard counts) is scoped to those clients, and anything outside them reads as "not found". Scripts are MSP-wide (admins edit them; they run anywhere) or belong to one client (its technicians edit them; they only run on its agents).
- **Policies:** every device sits in one device category (Windows, Linux or macOS, workstation or server, or one you make, such as kiosks) and uses one policy set from a tree that starts at *All devices*. Sets inherit everything above them and can override single fields; a client or one of its sites is assigned a set per category, and a single device can be pinned to its own. Alert policies, scheduled scripts, patching, the security policy, remote access and automatic agent updates all live there, and each device's page says which set it uses, why, and where each of its policies comes from. See [Policies](#policies).
- **Alerting:** alert policies, in a policy set (optionally limited to one client or site, minus devices you leave out), raise alerts for agents that are offline, CPU, memory or disk held over a threshold, a stopped or failed service, a failed script, a log entry that matches, failed patch installs and restarts left pending. Offline and threshold policies are checked every minute; the others act as agents report. An alert stays open until its condition clears (or someone resolves it), reminds its channels while nobody acknowledges it, and feeds the health model. Maintenance windows and snoozes hold alerts back during planned work. See [Monitoring and alerts](#monitoring-and-alerts).
- **Processes and files:** technicians see an agent's processes live and kill them (or a whole tree), and browse its file system, downloading and uploading files of any size in pieces over the agent's socket. Kills and transfers are audited.
- **Schedules:** saved scripts run on a cron timetable, in any time zone, on every device using a policy set (or a set below it), optionally limited to one client or site. Each schedule keeps its runs' output for as many days as you choose.
- **Patch management:** agents scan for OS updates (Windows Update Agent, apt, dnf/yum, pacman, softwareupdate) when they connect and every `RMM_PATCH_SCAN_HOURS`. The patch policy approves updates by category or severity and can install them during each site's maintenance window (or a window of its own, so servers and workstations at one site patch at different times), with a reboot policy. Technicians approve, decline and install from the Patches page or an agent's Patches tab, and the Compliance tab shows how many agents per client are fully patched. See [Patch management](#patch-management).
- **Endpoint protection:** agents report the antivirus the machine already has (Microsoft Defender and other Windows Security Center products, ClamAV, XProtect), and can run our own sensor: telemetry, behaviour rules and file scanning from signed content rolled out to canary clients first, quarantine, network isolation, triage packages and fleet-wide hunting. Technicians start scans and signature updates from the Security page or an agent's Security tab, and alert policies raise alerts for protection that's off or out of date and for threats. See [Endpoint protection](#endpoint-protection).
- **Self-update:** agents install new versions signed with an offline ed25519 key whose public half is compiled into the agent, and roll themselves back if the new version can't reconnect. See [Agent updates](#agent-updates).
- **Security:** argon2id passwords; opaque, revocable session tokens in an HttpOnly SameSite=Strict cookie, with an idle timeout and a 7-day cap; users can change their password and review or revoke their sessions, and admins can reset passwords, re-enable users, and revoke anyone's sessions; TOTP two-factor auth with single-use recovery codes, required for admins and optionally for everyone; an Origin check on the terminal and desktop sockets; three roles (admin / technician / readonly); an audit log covering logins, shells, remote desktop sessions, jobs, enrollment, and deletes. Failed sign-ins are rate-limited per client IP and per account, and bad enrollment tokens per IP (see `RMM_TRUSTED_PROXIES`). The dashboard ships a hash-based script CSP, so no inline or third-party script runs.

## Development

Requirements: Rust (stable, edition 2024), Node 24, Docker (for Postgres).

```sh
# 1. Database
docker compose -f docker-compose.dev.yml up -d
export DATABASE_URL=postgres://rmm:rmm@localhost:5432/rmm

# 2. First admin user (runs migrations too)
RMM_PASSWORD='choose-a-long-password' cargo run -p rmm-server -- create-user --email you@example.com --name You

# 3. Server (http://localhost:8080)
cargo run -p rmm-server

# 4. Dashboard, either built and served by the server...
npm --prefix web install && npm --prefix web run build
#    ...or with hot reload on http://localhost:5173 (proxies /api to :8080)
npm --prefix web run dev

# 5. Agent: in the UI, go to Clients & Sites → Enroll agents to get a token, then
cargo run -p rmm-agent -- --config ./agent.local.toml enroll --server http://localhost:8080 --token <TOKEN>
cargo run -p rmm-agent -- --config ./agent.local.toml run
```

`rmm-agent inspect` prints the metrics and inventory the agent would send, without needing a server.

**Tests.** `cargo test` runs the unit tests. The end-to-end test starts the real server against a
scratch database (created and dropped per run) and drives real agent processes through
enrollment, jobs across server and agent restarts, lost and expired jobs, per-client access,
packages and rate limits:

```sh
cargo build -p rmm-agent
RMM_E2E_DATABASE_URL=postgres://rmm:rmm@localhost:5432/postgres \
  cargo test -p rmm-server --test e2e -- --ignored --nocapture
```

`tests/e2e_windows.rs` is the Windows counterpart: it installs the agent from the generated MSI as
a real service and runs PowerShell and cmd jobs, a Job Object tree kill, a service restart, an
upgrade and an uninstall. It changes the machine it runs on, so it runs in CI (`windows-latest`)
or on a throwaway VM; see the file for the command.

The dashboard has visual regression and accessibility tests. Playwright screenshots every page,
in light and dark, against a mocked API, and runs WCAG 2.2 AA checks with axe. The baselines are
rendered in the Playwright Docker image, so run the tests there to match CI:

```sh
cd web
npm run test:visual:docker                          # compare against the baselines
npm run test:visual:docker -- --update-snapshots    # after an intended UI change
```

`npm run dev` also serves a component gallery at `/dev/ui`.

> **Note for this checkout:** the repo lives on a NAS mount that doesn't support symlinks, so
> `web/.npmrc` sets `bin-links=false` and the npm scripts call each tool's JS entry point directly.
> Use `npm`, not `pnpm`. pnpm's layout always needs symlinks.

## Deploying

```sh
cp deploy/.env.example deploy/.env      # set RMM_DOMAIN, POSTGRES_PASSWORD and RMM_DATA_KEY
docker compose -f deploy/docker-compose.yml up -d --build
docker compose -f deploy/docker-compose.yml exec server \
  sh -c 'RMM_PASSWORD=... rmm-server create-user --email you@example.com --name You'
```

Admins must set up two-factor auth (any authenticator app) at their first sign-in. If the
only admin loses their phone and recovery codes, clear it from the server:

```sh
docker compose -f deploy/docker-compose.yml exec server rmm-server reset2fa --email you@example.com
```

Caddy terminates TLS with an automatic certificate. Agents must use `https://` server URLs in
production; the agent verifies certificates against the OS trust store.

Behind any other reverse proxy, set `RMM_TRUSTED_PROXIES` to its address (or `private` if it's
on the same host or Docker network). Otherwise every request appears to come from the proxy, and
the sign-in rate limit applies to all users at once.

**Backups**

The `backup` service runs `pg_dump` every `BACKUP_INTERVAL_HOURS` (default 24) and keeps
`BACKUP_KEEP_DAYS` (default 14) of dumps in `deploy/backups/` (the `rmm-backups` volume in the
Arcane stack). The dumps contain password hashes, 2FA secrets (encrypted with `RMM_DATA_KEY`, so keep the key with the backups) and agent credential hashes, so
they're written mode 0600. Copy them off the host. To restore one into an empty database:

```sh
docker compose -f deploy/docker-compose.yml stop server
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_restore -U rmm -d rmm --clean --if-exists < deploy/backups/rmm-20260101T030000Z.dump
docker compose -f deploy/docker-compose.yml start server
```

Ticket attachments and raw inbound email aren't in the database: they're files in the `files`
volume (`rmm-files` in the Arcane stack), or in your S3 bucket. Back that up too.

**Upgrading**

Migrations run when the server starts and only go forward: there is no down migration. So an
upgrade is a backup, a new image, and a check; a rollback is restoring that backup.

1. **Back up**, right before, whatever the nightly job did: `docker compose -f
   deploy/docker-compose.yml exec -T db pg_dump -U rmm -Fc rmm > rmm-before-upgrade.dump`.
   Keep it with the `RMM_DATA_KEY` that was in use: the 2FA secrets in the dump are encrypted
   with it, and no other key opens them.
2. **Upgrade**: set the image tag (`RMM_TAG` in the Arcane stack; `git pull` then `up -d
   --build` for the build-from-source stack) and start it. The server applies new migrations
   and logs `listening on`; if a migration fails it exits instead of serving, and the database
   is left at the last migration that succeeded.
3. **Verify**: `/healthz` answers `ok`, agents show online again within a minute or two (they
   reconnect on their own), and a ticket, an agent page and the alert list open. With
   `RMM_METRICS_TOKEN` set, `rmm_agents_connected` should climb back to where it was.
4. **Roll back** only by restoring: stop the server, restore the dump into an empty database,
   and start the *old* image tag with the same `RMM_DATA_KEY`.

   ```sh
   docker compose -f deploy/docker-compose.yml stop server
   docker compose -f deploy/docker-compose.yml exec -T db dropdb -U rmm rmm
   docker compose -f deploy/docker-compose.yml exec -T db createdb -U rmm rmm
   docker compose -f deploy/docker-compose.yml exec -T db pg_restore -U rmm -d rmm < rmm-before-upgrade.dump
   git checkout v0.1.1   # the version you upgraded from
   docker compose -f deploy/docker-compose.yml up -d --build server
   ```

   (In the Arcane stack, set `RMM_TAG` back to the old version instead of checking it out.)

   Pointing an old image at an upgraded database doesn't work: it refuses migrations it doesn't
   know. Anything written between the backup and the rollback (tickets, metrics, alerts) is
   lost, so decide quickly.

CI checks this path on every push: the `upgrade` job builds a database with the previous
release's image and agent (an admin, a client and site, an enrolled agent with metrics, a
ticket), starts the new server on it, reads those rows back and runs the e2e suite there. A
migration that has shipped in a tag must never be edited (the job fails if one is); add a new
one instead.

**Installing an agent**

In the dashboard, open Clients & Sites → Enroll agents. The dialog has download buttons for the
agent, and the install commands it generates download the binary themselves (the enrollment
token authorizes the download), so one pasted command does everything. The server image ships
a static Linux x86_64 binary and a Windows x64 binary in `RMM_AGENT_DIR`. To install by hand:

For fleets managed with configuration management, **Create package** in the same dialog builds an
`.msi`, a `.deb` and an `.rpm` with the server URL and a dedicated token baked in. Installing a
package enrolls the machine and starts the service. Reinstalling or upgrading keeps the existing
enrollment (and doesn't spend a token use). Anyone holding the package can enroll machines into
that site, so its token always has an expiry and a use limit (30 days and 50 uses unless you set
others). Revoke the token once the rollout is done.

The MSI installs silently (`msiexec /i rmm-agent.msi /qn`), so Group Policy software
installation, Intune (as a line-of-business app) and other RMMs can push it. It puts the agent in
`C:\Program Files\RMM` and runs `rmm-agent.exe enroll --keep-existing --install` as SYSTEM; the
outcome is appended to `C:\ProgramData\RMM\logs\install.log`. Each download is a new version of
the same product, so installing a newer one replaces the old one. Uninstalling (Apps & features, or
`msiexec /x`) stops and removes the service but keeps `C:\ProgramData\RMM`, so a reinstall comes
back as the same agent. `RMM_SERVER` and `RMM_TOKEN` are public properties if you need to override
them: `msiexec /i rmm-agent.msi RMM_TOKEN=<TOKEN> /qn`.

```sh
# Linux (as root): copies itself to /usr/local/bin and installs a systemd unit
sudo ./rmm-agent enroll --server https://rmm.example.com --token <TOKEN> --install

# Windows (elevated PowerShell): copies itself to C:\Program Files\RMM and installs the
# "RmmAgent" service running as LocalSystem, restarted automatically on failure
.\rmm-agent.exe enroll --server https://rmm.example.com --token <TOKEN> --install
```

Config lives in `/etc/rmm-agent/agent.toml` (mode 0600) on Linux and in
`C:\ProgramData\RMM\agent.toml` on Windows, where the agent restricts `C:\ProgramData\RMM`
to SYSTEM and Administrators. Windows service logs go to `C:\ProgramData\RMM\logs\agent.log`.

## Server configuration

| Env var | Default | |
|---|---|---|
| `DATABASE_URL` | required | Postgres connection string |
| `RMM_BIND` | `0.0.0.0:8080` | Listen address (plain HTTP; put TLS in front) |
| `RMM_PUBLIC_URL` | `http://localhost:8080` | External URL; used in install commands and to set `Secure` cookies |
| `RMM_WEB_DIR` | `web/build` | Built dashboard |
| `RMM_AGENT_DIR` | `agents` (`/srv/agents` in the image) | Agent binaries offered for download: `rmm-agent-linux-x86_64`, `rmm-agent-windows-x86_64.exe` |
| `RMM_HEARTBEAT_SECS` | `30` | Agent metrics interval |
| `RMM_INVENTORY_SECS` | `21600` | Agent inventory interval |
| `RMM_METRICS_RAW_DAYS` | `7` | Raw heartbeat samples kept (charts up to 48 hours, threshold alerts) |
| `RMM_METRICS_RETENTION_DAYS` | `90` | Hourly metric rollups kept (charts beyond 48 hours) |
| `RMM_ALERT_RETENTION_DAYS` | `180` | Resolved alerts are deleted after this |
| `RMM_JOB_QUEUE_DAYS` | `7` | Jobs (and patch installs) queued for an offline agent expire after this |
| `RMM_PATCH_SCAN_HOURS` | `12` | Online agents scan for OS updates when their last scan is older than this |
| `RMM_SESSION_IDLE_HOURS` | `12` | Dashboard sessions unused this long are signed out (sessions last 7 days at most). Admins can override it under Company settings |
| `RMM_STORAGE_DIR` | `data/storage` (`/srv/data/storage` in the image) | Ticket attachments and raw inbound email, unless `RMM_S3_BUCKET` is set |
| `RMM_S3_BUCKET` | empty | Store those files in an S3-compatible bucket instead. With `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `RMM_S3_REGION` (default `us-east-1`), and `RMM_S3_ENDPOINT` for MinIO and other non-AWS stores (path-style URLs then; `RMM_S3_PATH_STYLE` overrides) |
| `RMM_MAIL_POLL_SECS` | `60` | How often IMAP support mailboxes are checked |
| `RMM_TICKET_CLOSE_DAYS` | `7` | Resolved tickets move to Closed after this |
| `RMM_PUBLIC_URL` callbacks | | QuickBooks and Xero redirect to `<RMM_PUBLIC_URL>/api/billing/accounting/qbo/callback` (or `/xero/callback`): register that in the provider's developer portal. For the QuickBooks sandbox set `RMM_QBO_API_URL=https://sandbox-quickbooks.api.intuit.com` |
| `RMM_EMAIL_RAW_DAYS` | `90` | Raw MIME of inbound mail is deleted after this (the ticket keeps the text and attachments) |
| `RMM_DATA_KEY` | empty (required by the compose files) | 32 bytes, hex or base64 (`openssl rand -hex 32`). Encrypts two-factor secrets and detection context at rest. Secrets stored before it was set are encrypted at the next start. Keep a copy off the server: if it's lost, users with 2FA can't sign in until `rmm-server reset2fa` clears it, and the server refuses to start without it once anything has been encrypted |
| `RMM_TRUSTED_PROXIES` | empty | Reverse proxies whose `X-Forwarded-For` gives the client IP (for rate limiting and the audit log): comma-separated addresses/CIDRs, or `private` for loopback + RFC 1918 + IPv6 ULA. The bundled compose stack sets `private` for Caddy |
| `RMM_ATTACHMENT_MAX_MB` | `100` | Largest ticket or portal attachment, per file. Uploads and downloads stream to and from storage (S3 multipart over 8 MB), so this bounds disk use, not server memory. Replies email attachments up to 15 MB in total; larger files go as links (the portal for contacts who can sign in, otherwise a download link valid for 30 days) |
| `RMM_METRICS_TOKEN` | empty | Turns on `GET /metrics` (see [Monitoring the server](#monitoring-the-server)); without it the route answers 404 |
| `RMM_LOG_FORMAT` | `text` | `json`: one JSON object per log line |

## Monitoring the server

**Metrics.** With `RMM_METRICS_TOKEN` set (`openssl rand -hex 32`), `GET /metrics` answers in
the Prometheus text format to requests with `Authorization: Bearer <token>` (compared in
constant time; anything else gets 401). It sits outside `/api`, so it goes through your proxy
like everything else: scrape it from inside the network if you can. Labels are bounded: route
templates (`/api/tickets/{id}`), message types and status classes, never an agent, client, user
or ticket id. What's there:

| Series | |
|---|---|
| `rmm_agents_connected`, `rmm_agent_connects_total`, `rmm_agent_auth_failures_total` | Agents online on this server, sessions started, refused credentials |
| `rmm_agent_messages_total{type}`, `rmm_agent_message_bytes_total` | What agents send, by message type |
| `rmm_hub_send_queue_depth`, `_max`, `_capacity`; `rmm_hub_dropped_total{reason}` | Messages waiting for agents (all, and the fullest queue), and sends that were thrown away |
| `rmm_sse_subscribers`, `rmm_sse_lagged_events_total`, `rmm_sse_resyncs_total` | Open dashboards, and how often one fell behind the event stream |
| `rmm_outbox_pending{outbox}`, `rmm_outbox_oldest_seconds{outbox}` | Notifications and emails waiting to go out, and the age of the oldest |
| `rmm_alert_eval_duration_seconds`, `rmm_alert_eval_interval_seconds` | Time for one pass over the polled alert policies, and how often a pass starts |
| `rmm_scheduler_tick_duration_seconds` | Scheduled scripts: one tick |
| `rmm_http_requests_total{method,route,status}`, `rmm_http_request_duration_seconds` | Requests and time to response headers |
| `rmm_db_pool_connections`, `_idle`, `_max`, `rmm_db_pool_acquire_seconds`, `rmm_db_pool_acquire_timeouts_total` | The Postgres pool (the acquire time is sampled every 5 seconds) |
| `rmm_shell_sessions`, `rmm_desktop_sessions` | Open terminals and remote desktops |
| `process_resident_memory_bytes`, `process_cpu_seconds_total`, `process_open_fds`, `process_threads` | The server process (Linux) |
| `rmm_build_info{version}`, `rmm_uptime_seconds` | |

```yaml
# prometheus.yml
scrape_configs:
  - job_name: rmm
    scheme: https
    metrics_path: /metrics
    authorization: { type: Bearer, credentials_file: /etc/prometheus/rmm-token }
    static_configs: [{ targets: ["rmm.example.com"] }]
```

The alerts worth having:

```yaml
groups:
  - name: rmm
    rules:
      - alert: RmmAgentsDropping        # a fifth of the fleet gone in 10 minutes: network, proxy or server
        expr: rmm_agents_connected < 0.8 * max_over_time(rmm_agents_connected[1h] offset 10m)
        for: 5m
      - alert: RmmOutboxBacklog         # notifications or email not going out (SMTP down, webhook failing)
        expr: rmm_outbox_oldest_seconds > 900
        for: 10m
      - alert: RmmAlertEvaluationSlow   # a pass takes longer than the interval: alerts arrive late
        expr: rate(rmm_alert_eval_duration_seconds_sum[15m]) / rate(rmm_alert_eval_duration_seconds_count[15m]) > rmm_alert_eval_interval_seconds
        for: 15m
      - alert: RmmDatabasePoolExhausted # requests waiting for a database connection
        expr: increase(rmm_db_pool_acquire_timeouts_total[10m]) > 0 or (rmm_db_pool_idle == 0 and rmm_db_pool_connections == rmm_db_pool_max)
        for: 5m
      - alert: RmmDown
        expr: up{job="rmm"} == 0
        for: 2m
```

**Logs.** Text by default; `RMM_LOG_FORMAT=json` writes one JSON object per line for log
shippers. Every request is logged once by `rmm_server::http` with its method, route template,
status, duration and a request id (also returned as `X-Request-Id`, and attached to anything
else logged while handling it). Query strings (portal sign-in links and survey tokens travel
there), bodies and headers are never logged. `RUST_LOG=info,rmm_server::http=warn` keeps only
failed requests.

**Capacity.** One server and the default Postgres container on a desktop-class machine were
load tested at 1,000 and 10,000 simulated agents: see
[docs/research/load-test-2026-11.md](docs/research/load-test-2026-11.md) for the numbers and
what gives out first. In short: one server held 10,000 agents with the server process at a
quarter of a core; Postgres is what to size. Give it a disk with a fast fsync (NVMe, ideally
with power-loss protection, not a copy-on-write filesystem such as btrfs), and budget about
4.5 MB of database per agent at the default metric retention. `rmm-loadgen` repeats the test
against your own hardware.

## Policies

**Policies** (Monitoring → Policies) has three tabs.

- **Policy sets**: one tree. *All devices* is the root, with Windows, Linux and macOS below it and
  a workstation and a server set below each of those. Add your own sets anywhere below (eight
  levels at most): MSP-wide ones, or sets that belong to one client, which only its devices can use
  and its technicians can change. Each row shows how many devices use the set and what it defines
  or overrides.
- **Device categories**: every device is in exactly one. The six built-in ones (Windows, Linux,
  macOS × workstation, server) fill themselves from what the agent reports; a custom category
  (kiosks, SQL servers) is filled by hand from the Agents list (**Change category**) or by an
  enrollment token that names it. Each category has a default set.
- **Assignments**: per client, the set each category uses, for the whole client or one site.

**Which set a device uses** is the first of: a set pinned to it, the set assigned to its site for
its category, the one assigned to its client, the category's default. The agent's **Policy** section
says which and why, lets technicians change its category, pin a set, or **Customize for this
device** (a new set below its current one, named after the host and pinned to it), and lists every
policy that reaches it with the set it's defined in and the sets that change it.

**Inheritance.** A set gets every policy of the sets above it. Alert policies and scheduled scripts
can be added to any set (and optionally limited to one client or site, minus single devices).
Patching, the security policy, remote access and the agent policy exist once, in All devices. On a
set's page each policy, and each of its fields, says whether it's defined here, inherited (and from
which set) or overridden here. Changing an inherited field stores only that field in the set's
override; **Reset** next to it goes back to the inherited value, and **Reset all** drops the
override. A scheduled script's timetable stays the same everywhere; sets below can change its
arguments and timeout, or switch it off. A change that would leave any set below with an invalid
policy is refused with the name of that set.

## Monitoring and alerts

**Alert policies** say what to watch. They live in [policy sets](#policies) (a set's **Alerts**
section) and apply to every device using that set or one below it. Admins write MSP-wide ones;
technicians write ones limited to the clients they can see, or in a client's own sets. Each has a
severity: open critical alerts make an agent *unhealthy*, warnings make it *need attention*. An
alert policy can also run a saved script on the device when its alert opens (once; while a
maintenance window holds the alert back, when the window ends), and the alert links to that job.

| Type | Opens when | Clears when |
|---|---|---|
| Agent offline | no heartbeat for N minutes (after a server restart, agents get N minutes to reconnect) | the agent reconnects |
| CPU / memory / disk | every sample in the last M minutes is at or above the threshold (disk: the fullest volume) | the last 5 minutes are all below it |
| Service stopped | a watched service is stopped or failed. Watch names (`nginx`, `Spooler`, `php*-fpm`), every automatic service, or both, minus exclusions | it runs again |
| Failed job | a script fails, errors or times out (any script, or one) | the same script next succeeds on that agent |
| Event log match | a journal entry (Linux) or Event Log entry (Windows) matches the level, sources, event IDs and regular expression | someone resolves it |
| Patches | an update failed to install (one alert per agent), or a restart to finish updates has been pending for N hours | the updates install or are declined; the restart happens |
| Antivirus | no product on, real-time off, signatures older than N hours, a threat, our sensor down, or an online agent that hasn't reported its protection state for N hours (agents resend it at least hourly) | the condition goes away |

**Leaving one agent out.** The agent's Policy section lists the policies that reach it and can leave
it out of any alert policy or scheduled script (its open alerts from that policy close quietly).
The policy lists its excluded devices where it's defined.

**Maintenance windows and snoozes** hold alerts back for a client, a site or one agent: a one-off
period (snooze an agent from its page before planned work) or a weekly window (at the bottom of the
Alerts page, e.g. weekend patching). Alerts that open meanwhile are recorded but marked
muted: nobody is notified, no ticket opens, and they don't count against health. Any still open
when the window ends are announced then, as if they had just opened.

Agents report their services (systemd units, Windows services) once a minute when something changed,
and technicians can start, stop and restart them from the agent's Services tab. Log watchers run on
the agent, which sends at most 20 matches a minute per policy and counts the rest; matched entries
are kept for 30 days on the agent's Event log tab.

**Notifications** go to channels set up by an admin under Company settings → Notifications: email
(through the SMTP server set there), a generic webhook, Slack incoming webhooks, or Teams Workflows
webhooks (Adaptive Cards). A policy notifies its channels when an alert opens and, optionally, when
it clears, and can remind them every 15 minutes to 3 days while the alert stays open and
unacknowledged (not during a maintenance window). Deliveries are queued in Postgres and retried (after 1, 5 and 30 minutes, then every 2
hours, 5 attempts in all), so a mail server outage delays them rather than losing them. The delivery
log is on the same settings page.

A webhook receives a JSON body like this, with `X-RMM-Event: opened|resolved|reminder|test`, and, when the
channel has a secret, `X-RMM-Signature: sha256=<hex HMAC-SHA256 of the body with the secret>`:

```json
{
  "event": "opened",
  "alert": { "id": "…", "kind": "disk", "severity": "critical", "title": "Disk at or above 90% for 5 minutes",
             "details": { "value": 96.2, "threshold": 90, "minutes": 5 }, "occurrences": 1,
             "opened_at": "…", "resolved_at": null, "resolution": null, "policy": "Disk nearly full" },
  "agent": { "id": "…", "hostname": "acme-fs01", "client": "Acme Corp", "site": "Head office" },
  "url": "https://rmm.example.com/agents/…?tab=alerts"
}
```

**Metrics storage.** Heartbeats land in `agent_metrics` and are rolled up into
`agent_metrics_hourly` every few minutes. Charts up to 48 hours read raw samples; longer ranges (up
to 90 days by default) read the rollups. Raw samples are kept for `RMM_METRICS_RAW_DAYS`, so the raw
table stays at about a week of heartbeats however long the history is. That is what keeps Postgres
comfortable into the thousands of agents. TimescaleDB would be the next step beyond that.

## Agent updates

Agents update themselves to a newer version that is signed with your release key. The server
can offer a binary but can't forge one: the public key is compiled into the agent, and the
private key stays on a build machine or in CI.

1. Create the key once, and keep it (and a backup) safe:
   `cargo run -p rmm-sign -- keygen --out release.key`. It prints `RMM_UPDATE_PUBKEY=…`.
2. Build agents with that public key: `RMM_UPDATE_PUBKEY=<hex> cargo build --release -p rmm-agent`.
   The image workflow does this from the repository variable `RMM_UPDATE_PUBKEY`. Agents built
   without a key refuse all updates.
3. Sign each release: `rmm-sign sign --key release.key --platform linux-x86_64 --version 0.2.0 rmm-agent-linux-x86_64`
   writes `rmm-agent-linux-x86_64.update.json` next to the binary. In the image workflow, set the
   secret `RMM_UPDATE_SIGNING_KEY` (the key file's contents) and push a `v0.2.0` tag.
4. Put the binary and its `.update.json` in `RMM_AGENT_DIR` (the image already has them there).
   Agents → **Update N outdated** (or the agent page's **Update** button) offers it. Turn on
   **Update agents automatically** in the agent policy (Policies → All devices → Agent, or any set
   below it, say to leave servers to be updated by hand) to offer it whenever an agent connects.

The agent checks that the version is newer than its own, downloads it over its socket, and
verifies the checksum and signature. It then waits for running jobs to finish (at most 30 minutes)
and hands over to a watchdog: a copy of the old binary, run outside the service (a transient
systemd unit, or a detached process on Windows). The watchdog swaps the binaries and restarts the
service. If the new version hasn't reconnected within 120 s, it restores the old binary and the
agent reports `rolled_back`. Automatic updates don't retry a version that failed on that agent.
Watchdog logs: `journalctl -u 'rmm-agent-update-*'` on Linux, `C:\ProgramData\RMM\logs\update.log`
on Windows.

Updates need the agent running as a service (systemd or the Windows service). Agents installed
from a `.deb`/`.rpm`/`.msi` update in place, and a later package upgrade replaces the binary again.

## Patch management

Each agent scans with its OS's own update mechanism:

| OS | Scan | Install |
|---|---|---|
| Windows | Windows Update Agent API (`IUpdateSearcher`, software and drivers); PSWindowsUpdate if the API can't be reached | `IUpdateDownloader` + `IUpdateInstaller`. If Windows needs a restart before it can install (`RebootRequiredBeforeInstallation`), the install reports that instead of trying |
| Debian, Ubuntu | `apt-get update`, then `apt-get -s dist-upgrade`. Updates from a `*-security` suite count as security | `apt-get install --only-upgrade`, non-interactive, keeping existing config files |
| RHEL, Fedora | `dnf check-update --refresh` (or `yum`), with `dnf updateinfo` for advisories, severity and security | `dnf -y upgrade <name.arch…>` |
| Arch | `checkupdates` (install `pacman-contrib`) | `pacman -Syu`: always everything, because Arch doesn't support partial upgrades |
| macOS | `softwareupdate -l` | `softwareupdate -i`, one update at a time |

`rmm-agent patches` runs a scan in the foreground and prints what the server would get, and
`rmm-agent patches --install ID…` installs. Both are useful for debugging a machine.

**Approval.** The patch policy approves updates by category (security, critical, definitions,
rollups, updates, drivers, feature updates) or by vendor severity (critical, important, moderate,
low; only Windows and RHEL/Fedora rate updates). It's set in All devices (Policies, or **Patch
policy** on the Patches page), which by default approves security, critical and definition updates
and installs nothing on its own, and any [policy set](#policies) below can override single fields
of it, so one client's servers can install automatically while the rest don't. A person's approve or decline overrides the policy until someone resets it. Made for a
client, a site or everything (rather than picked agents), it also covers agents that report the
update later; resetting the scope hands the update back to the policy. Declined updates don't count
against compliance.

**Health.** Security or critical updates missing for more than a week, updates that failed to
install, and a restart pending for more than a day make an agent *need attention*. A `patch` alert
policy turns failed installs and long-pending restarts into alerts.

**Installing.** With **Install automatically** on, the server starts installs for approved
updates (after the policy's deferral, counted from when the update was first seen) while the
site's maintenance window is open, or the policy's own install window when it has one. A site without a window installs whenever updates are
eligible. Installing by hand from the dashboard starts right away, ignoring windows and
deferrals. The reboot policy (never, if required, always) decides whether the agent restarts the
machine afterwards, with a one-minute warning. Failed updates are retried automatically up to
three times. Agents report results after reconnects, like job results. After every install the
agent rescans, so the dashboard shows what is really installed. On Linux under systemd the
package manager runs in its own transient scope (`systemd-run --scope`) and writes to files rather
than pipes, so restarting or updating the agent mid-install doesn't kill dpkg or rpm halfway.

Limits: Debian/Ubuntu/Arch don't publish severities, so approve those by category (Arch has no
security tags either: include **Updates** in the policy for Arch machines). On Apple silicon,
macOS updates that need a restart may need a signed-in user to approve them. The Windows provider
is compile-checked only so far, like the rest of the Windows agent.

## Service desk (tickets)

**Tickets** (Service desk → Tickets) live on **boards** (queues such as Service Desk and Alerts), each
with its own statuses. Every status belongs to a category (New, Open, Waiting on client, Waiting on
vendor, Resolved, Closed), which drives the views, reopening and auto-closing. Boards, ticket types
and support mailboxes are under Company settings → Service desk.

- **Timeline:** public replies (emailed to the contact), internal notes, every field change, alert
  events, script results and remote sessions, in one append-only history. Attachments are stored
  in `RMM_STORAGE_DIR` or S3; images preview inline, everything else downloads.
- **The RMM link:** a ticket lists the agents it's about with their live state (online, CPU,
  memory, disk, open alerts, missing updates). From there a technician runs a script (the output
  lands on the timeline as an internal note) or opens a terminal or remote desktop (start and end,
  with the duration, are recorded).
- **Alerts open tickets:** an alert policy can file tickets on a board with a priority. A repeat of
  the same alert on the same agent adds to its open ticket; a return after it was resolved reopens
  it. Optionally the ticket resolves itself when the alert clears, unless a person has worked it
  or the alert has come back three times.
- **Email:** support mailboxes receive mail over IMAP (polled every minute, messages marked read),
  Microsoft 365 over Graph (an Entra app with Mail.ReadWrite and Mail.Send; replies are sent through
  the mailbox too, since basic-auth SMTP is usually off there), or a provider webhook (`POST /api/inbound/email/<secret>`: raw MIME, Postmark JSON with the raw
  email, or a Mailgun `mime` route). Replies thread by the `[T-10423]` subject tag, then by
  `In-Reply-To`/`References`; quoted history is stripped. Senders are matched to contacts by
  address, then to clients by their email domains; unknown senders land in **Triage** (visible only
  to users who see every client). Auto-replies, bulk and list mail, bounces and mail from our own
  addresses are recorded and ignored, and acknowledgements are limited to three per sender per
  hour, so two systems can't reply to each other forever. Outgoing mail uses the SMTP server under
  Notifications, with Reply-To set to the mailbox.
- **Contacts** belong to a client (Clients → a client → Contacts). They're never created from mail
  automatically.
- Search covers ticket numbers, subjects, every timeline entry and contact names (Postgres full
  text), in the Tickets list and the command palette. Bulk actions: assign, status, priority, team;
  merge duplicates from a ticket's menu, or split one message off into a new ticket.
- **Teams** (Company settings → Service desk): tickets can belong to a team as well as a person,
  boards can default new tickets to one, and members get a "My teams" view. Boards can also announce
  new tickets on notification channels.
- **Canned responses and macros:** saved replies with `{{contact.first_name}}`, `{{ticket.number}}`
  and similar variables, inserted from the reply box; a macro also sets the status, priority or
  assignee when the reply goes out. Shared ones are managed by admins, everyone can keep their own.
- **SLAs** (Company settings → SLAs): policies with first-response, update and resolution targets per
  priority, in business hours (a time zone, opening hours and holidays) or around the clock. The
  default policy covers clients without one of their own, a client can have its own, and an active
  contract's policy comes first. Deadlines are stored on the ticket (so the list sorts by them and has
  "SLA missed" and "Due soon" views); the clock stops while a ticket waits on the client or sits
  resolved. At 75% of a target, and again on a breach, the policy's notification channels and the
  assignee hear about it, and the timeline records it.
- **Satisfaction surveys:** when switched on, each resolved ticket's contact gets one email with
  Good / Bad links (no sign-in); answers show on the ticket and in reports.

### Client portal

Contacts with portal access (on the client's Contacts tab, which can also send an invitation) sign in
at `/portal` with a one-time link emailed to them, or a password they set, optionally with a TOTP
code. Portal sessions are separate from technician sessions (their own table and a cookie scoped to
`/api/portal`), and everything is limited to the contact's client. Contacts see and reply to their
tickets (primary contacts, and contacts allowed to, see all of the client's), open new requests with
attachments, mark a ticket resolved, read public knowledge base articles, and, when the client allows
it, a read-only list of the client's devices. Billing contacts also see the client's invoices.

## Time and billing

Billing pages and amounts need the `billing.read` / `billing.manage` permissions (admins by default;
give them to others under Users → Permissions). Technicians log time without seeing rates.

- **Time:** a timer or entries by hand, on a ticket, a project or a client, with a work type (remote,
  onsite, after hours, …) and a billable flag. Time on a ticket is noted on its timeline, and the note
  can go out as a reply. Technicians submit a week; someone with `time.approve` approves or rejects
  it. Submitted weeks are locked, and billed time is locked for good.
- **Rates**, first match wins: the contract's rate for the work type, the technician's work role, the
  work type's rate, the technician's own rate, the company default.
- **Contracts** per client: per device (counted from the enrolled agents on the run date, optionally
  only workstations or servers), per user, block hours (a bank bought each cycle, drawn down by
  approved time; the rest bills at the overage rate; the account manager is warned when it runs low),
  time and materials, and flat recurring fees with items. Monthly, quarterly or annual cycles aligned
  to the calendar, prorated by day for contracts starting or ending mid-cycle. Covered work types are
  free on per-device, per-user and recurring contracts.
- **Invoices** (Billing): the invoice run makes a draft per client with the cycles due, device and
  user counts (snapshotted on the line), approved billable time and products sold on tickets.
  Nothing is billed twice; deleting a draft gives it all back. Drafts can be edited; finalising gives
  them a number without gaps (from a locked counter) and a PDF that never changes, and they can be
  emailed to the client's billing contacts with the PDF attached. Corrections are credit notes.
  Money is integer minor units with a currency per client (the company's by default).
- **Accounting:** connect QuickBooks Online or Xero (Company settings → Billing) over OAuth; finalised
  invoices and credit notes are pushed with their customers, and payments come back, every 10
  minutes or on demand. Tax comes from the accounting system's defaults.
- **Projects** with tasks (which can become tickets), a budget in hours and a burn-down from the time
  logged on the project and its tickets; a **schedule** of who works on what, when; **client
  documentation** pages with their history (Clients → a client → Docs); and **reports**: service desk
  volume, backlog age, response and resolution times, SLA attainment and satisfaction; utilisation;
  client profitability; and a quarterly business review PDF per client.

Not built: a password vault (it would need its own security review first).

## Remote desktop

Open an agent and choose **Remote desktop** (technicians and admins). The agent starts a helper
process (`rmm-agent desktop-helper`) inside the machine's graphical session, which captures the
screen and injects input; the agent relays between it and the server over its one socket.

| OS | Session | Capture | Input |
|---|---|---|---|
| Windows | The console session. The helper runs as SYSTEM there, so it follows input to the sign-in screen and UAC prompts | GDI `BitBlt` | `SendInput`; Ctrl+Alt+Del through `SendSAS` |
| Linux | The X11 display in use (a signed-in user's, else the display manager's greeter). The helper runs as that display's user | MIT-SHM, else `GetImage` | XTEST |

- The screen is compared in 64×64 tiles and only changed areas are sent, as JPEG. **Low**
  quality halves the resolution for slow links. At most two frames are in flight; the browser
  acknowledges each one it has drawn, so the frame rate (up to 20 fps) adapts to the link.
- Keys are sent by physical position, so the remote machine's own keyboard layout applies.
  **Type text** types a string independently of the layout (handy for passwords).
- Multiple monitors: pick one from the toolbar.
- **Consent:** the remote access policy (a policy set's **Remote access** section) can turn on
  **Ask the user before a remote desktop session starts**, and can switch remote desktop, the
  terminal or file access off; a refused session names the set that turned it off. The person at the machine gets an Allow/Deny prompt (a message box on Windows; zenity, kdialog
  or xmessage on Linux) and the session is refused if nobody answers within 30 seconds. If
  nobody is signed in, there is nobody to ask and the session starts.
- Every session is in the audit log (`desktop.open`, `desktop.close` with its duration).

Limits: Wayland sessions aren't supported yet (the agent says so; choose an Xorg session at the
sign-in screen), there's no clipboard sync or session recording, and the Windows side is
compile-checked only, like the rest of the Windows agent. `RMM_DESKTOP_FAKE=<file>` makes the
agent serve a synthetic screen and log input to `<file>`, for testing without a display.

## Endpoint protection

Agents report the protection the operating system already has. Nothing replaces it: the agent
reads its state and drives its scans.

| OS | Product | State from | Actions |
|---|---|---|---|
| Windows | Microsoft Defender | `Get-MpComputerStatus`, `Get-MpThreatDetection` | Quick scan, full scan (`Start-MpScan`), signature update (`Update-MpSignature`) |
| Windows | Any other antivirus registered with Windows Security Center (workstations) | `root/SecurityCenter2` (on/off, signatures current) | None: manage it in its own console |
| Linux | ClamAV | `clamscan --version` (signature version and date), `clamonacc` for real-time | Quick scan (home and temporary directories; through `clamd` when it runs), full scan (every top-level directory, one filesystem each, at low priority), signature update (`freshclam`, or restarting the freshclam service) |
| macOS | XProtect (always on), Gatekeeper | The XProtect bundle's version and date, `spctl --status` | Signature update (`xprotect update`, macOS 15+) |

The agent sends its state after connecting, whenever it changes (checked every 5 minutes) and
when asked. The **Security** page shows every agent by protection state: **Active threats**,
**Unprotected** (no product on), **At risk** (real-time protection off, or signatures over 72 hours
old), **No data** and **Protected**, plus the detections across the fleet. An agent's
**Security** tab shows each product, its detections and the scans and updates started from the
dashboard. One scan or update runs per machine at a time; ClamAV's findings are remembered by the
agent (`/var/lib/rmm-agent/security/clamav.json`) because ClamAV keeps no history.

**Alerts.** An **Antivirus** alert policy can alert when no antivirus is on, real-time protection
is off, signatures are older than N hours, and on threats: either each active threat (cleared
once it's quarantined or removed) or every new detection, even one already quarantined (stays
open until someone resolves it). Alerts feed agent health and can open tickets like any other.

`rmm-agent security` prints what the agent would report, and `rmm-agent security --run
quick_scan` (or `full_scan`, `update_signatures`) runs an action in the foreground.
`RMM_SECURITY_FAKE=<file>` (debug builds) reads the state from a JSON file instead, for tests.

### Our own sensor

Turn it on in the security policy (Policies → All devices → Security, or any set below it for some devices only; it's off in All devices by default). The agent then starts `rmm-agent sensor`, a separate process it restarts if it crashes, which:

- records telemetry (process starts with their parents and image hashes, network connections, changes to autostart locations, SSH keys and profiles, Windows Run keys and services, kernel modules) in a local store capped by the policy (`telemetry_mb`). It stays on the machine; the console queries it (an agent's Security tab, the detection page, and **Hunt** across the fleet).
- runs behaviour rules on every event, scans files (quick and full scans on the policy's schedule, one path on demand, every program as it starts) with its own engine (hash signatures, YARA rules and heuristics, looking inside zip/gzip/bzip2/xz/tar archives, Office macros, shortcuts and PDF/HTML scripts; files unchanged since a clean scan aren't read again), and watches ransomware decoys it places in each user's folder.
- quarantines what scans find (high and severe, with **auto-quarantine** on) into a store only root/SYSTEM can read. Files can be restored byte for byte, optionally excluding their hash. The operating system's own files and the agent are never quarantined automatically.

Detection content is a signed bundle, never code from the server:

```sh
rmm-sign test-content content/starter.json                    # rule tests + benign corpus
rmm-sign sign-content --key release.key content/starter.json  # writes content/starter.json.sig
```

Upload both files under **Security → Content**. A new version goes to canary clients first, and everyone gets it after `RMM_CONTENT_SOAK_MINUTES` (1440) unless the canaries show trouble (the sensor crashing, new rules firing widely, or a false-positive verdict), in which case it's rolled back. Agents verify the signature with the release key they were built with (`RMM_UPDATE_PUBKEY`); set the same variable on the server to check uploads there too. `content/build_starter.py` regenerates the starter bundle.

Hash signatures and YARA rules come in a **signature database**, a separate signed file built offline from feeds you download yourself:

```sh
rmm-sign build-db --key release.key --version 2026.11.15.1 --rules content/yara \
    --sha256 sha256_hashes.txt --yara yara-forge-core.yar --clamav main.hdb --benign /usr/bin --out sigs.rmmdb
rmm-sign inspect-db --pubkey <hex> --rules sigs.rmmdb
```

`build-db` imports plain SHA-256 lists and MalwareBazaar CSV exports, YARA rule files (YARA Forge packages, for example) and ClamAV `.hdb`/`.hsb` hash signatures, adds the first-party rules in `content/yara`, and refuses to write the file if any first-party rule fails its samples or anything other than an audit-mode heuristic matches the benign files. `content/feeds-example` shows each format. **Which feeds you may use commercially is yours to check:** MalwareBazaar data is CC0, YARA Forge and other rule sets carry their own licences (kept with each rule and shown in the console), and ClamAV's signatures are GPL. Upload the `.rmmdb` with `POST /api/security/databases` (the file as the body; there's no console page for it yet); it goes through the same canary stages and automatic rollback as content, agents download it over HTTPS with their own credentials, check its signature, and keep the previous version to fall back on. Rolling back the general version brings back the one before it. Building the agent with `--no-default-features` leaves the YARA engine out (about 1.5 MB smaller): hash signatures still match and the agent reports the rules as unsupported.

**Real-time protection** (policy field `realtime`: `off`, `audit` or `block`; `scan_on_write`; `archive_depth`; in the security policy of a policy set). On Linux, with the sensor running as root, every program is checked before it runs (fanotify exec permission events, on every local filesystem; network, FUSE and pseudo filesystems are skipped) and files are scanned after they're written. **Block** refuses a program that matches a hash signature or a high-confidence blocking rule with **prevention** on; **audit** decides the same way but never refuses or acts. A check that takes longer than 500 ms lets the program run and finishes in the background (then kills and quarantines it if it must). Our own processes are never held up and package-manager writes are never quarantined. Without fanotify permission events (an old kernel, a container without `CAP_SYS_ADMIN`) and on Windows and macOS, programs are scanned just after they start, and the agent's Security status says so. `scripts/test-onaccess.sh` runs its tests as root in a privileged container.

**Reputation.** Agents ask the server, in batches and once per hash, about programs their own database doesn't know; a known hash raises an alert (never a block or quarantine: the answer isn't signed). The server's set is the newest database plus hash lists that agents never download (`PUT /api/security/reputation/lists/{name}?severity=high`, one SHA-256 per line, optionally with a name), so a large feed can live on the server only. `GET /api/security/prevalence?sha256=` answers which machines have run a hash and since when, and `GET /api/security/reputation/rare` lists programs seen on few machines: hunting leads, counted within the clients a technician can see.

Rules start in **audit** mode (recorded, not alerted). Promote them under **Security → Rules** once their hit counts and verdicts look right; **disabled** is a fleet-wide kill switch. **Block** (kill the process or quarantine the file) needs a high-confidence rule, 7 days in general content without false positives, and **prevention** on in the policy.

Response actions (technicians with `security.respond`): kill a process tree, quarantine/restore/delete files, isolate the machine (only the RMM server, DNS and DHCP stay reachable; nftables/iptables, Windows Firewall or pf), and collect a triage package (.tar.gz of processes, connections, autoruns, logs and recent telemetry). Every action is audited. Permissions: `security.read`, `security.respond`, `security.manage`, granted by role or set per user under **Company settings → Users**.

`RMM_DATA_KEY` (see Server configuration) also encrypts detection context at rest: it contains command lines, which can contain passwords.

Limits: the Windows and macOS sensors are compile-checked only and poll for processes (fast short-lived processes can be missed; ETW and Endpoint Security are planned); on Linux the real-time process source and on-access protection need root. ClamAV's own on-access detections aren't collected yet. See the roadmap for the rest.

See [docs/ROADMAP.md](docs/ROADMAP.md) for what's next: the rest of the PSA and more.
