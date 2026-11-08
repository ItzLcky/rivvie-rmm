# RMM

A self-hosted, multi-tenant remote monitoring and management platform for MSPs.
The agent and server are written in Rust; the dashboard is a SvelteKit SPA.

| Platform | Status |
|---|---|
| Linux agent | Working: inventory, metrics, scripts, terminal, systemd service |
| Windows agent | Code complete, compile-checked in CI only (registry inventory, PowerShell/cmd, ConPTY, Windows service). Needs testing on a real host. |
| macOS agent | Builds; metrics and scripts work. No launchd install or software inventory yet. |

The release agent is a **2.7 MB** single binary that idles at **~8 MB RSS** with 5 threads.

## Layout

```
crates/
  rmm-proto/    Wire protocol shared by agent and server (MessagePack over WebSocket)
  rmm-agent/    Endpoint agent: collector, script runner, PTY shell, service install, self-update
  rmm-server/   axum server: agent hub, REST API, terminal relay, serves the dashboard
    migrations/ Postgres schema (applied automatically on start)
    tests/      End-to-end test: real server, Postgres and agent processes
  rmm-sign/     Offline release signing for agent self-update (never deployed to the server)
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
 │  browser  │   wss://…/api/agents/{id}/shell (terminal)    │  shell relay │
 └───────────┘ ◄───────────────────────────────────────────► └──────────────┘
```

- **Tenancy:** clients → sites → agents. Enrollment tokens are scoped to a site, so an agent lands in the right client automatically.
- **Enrollment:** `rmm-agent enroll --server URL --token T` swaps a time- and use-limited token for a permanent per-agent secret. The server stores only a SHA-256 of it. Re-enrolling a machine that still has its config keeps its agent record (the agent proves it holds the old secret); a token alone always creates a new record, so a leaked token can't take over existing agents. The agent refuses plain `http://` servers other than localhost unless you pass `--insecure`.
- **Transport:** the agent dials out, so endpoints need no inbound ports. Everything is multiplexed over one WebSocket: heartbeats (every 30 s), inventory (every 6 h or on demand), script jobs, and PTY streams. The agent reconnects with jittered exponential backoff, and treats 100 s of silence from the server as a dead connection.
- **Jobs:** sending a script to an offline agent queues it, and it runs on reconnect (queued jobs expire after `RMM_JOB_QUEUE_DAYS`). Output streams into Postgres (capped at 1 MB per stream). Jobs outlive the connection: the agent keeps a copy of each job's output and its result, and resends them after a reconnect or server restart until the server acknowledges them. A job is only marked `lost` when the agent comes back without it (the agent itself restarted) or never comes back. Timeouts kill the whole process tree on Unix, and closing a terminal kills everything started from it.
- **Terminal:** xterm.js ↔ server relay ↔ PTY on the agent (bash/zsh on Linux, PowerShell through ConPTY on Windows).
- **Per-client access:** admins see every client. Technicians and read-only users see every client by default, or only the clients an admin picks under Company settings → Users. Everything they can reach (agents, sites, tokens, jobs, terminal, dashboard counts) is scoped to those clients, and anything outside them reads as "not found". Scripts are MSP-wide (admins edit them; they run anywhere) or belong to one client (its technicians edit them; they only run on its agents).
- **Self-update:** agents install new versions signed with an offline ed25519 key whose public half is compiled into the agent, and roll themselves back if the new version can't reconnect. See [Agent updates](#agent-updates).
- **Security:** argon2id passwords; opaque, revocable session tokens in an HttpOnly SameSite=Strict cookie, with an idle timeout and a 7-day cap; users can change their password and review or revoke their sessions, and admins can reset passwords, re-enable users, and revoke anyone's sessions; TOTP two-factor auth with single-use recovery codes, required for admins and optionally for everyone; an Origin check on the terminal socket; three roles (admin / technician / readonly); an audit log covering logins, shells, jobs, enrollment, and deletes. Failed sign-ins are rate-limited per client IP and per account, and bad enrollment tokens per IP (see `RMM_TRUSTED_PROXIES`). The dashboard ships a hash-based script CSP, so no inline or third-party script runs.

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
enrollment, jobs across a server restart, lost and expired jobs, per-client access, packages and
rate limits:

```sh
cargo build -p rmm-agent
RMM_E2E_DATABASE_URL=postgres://rmm:rmm@localhost:5432/postgres \
  cargo test -p rmm-server --test e2e -- --ignored --nocapture
```

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
cp deploy/.env.example deploy/.env      # set RMM_DOMAIN and POSTGRES_PASSWORD
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
Arcane stack). The dumps contain password hashes, 2FA secrets and agent credential hashes, so
they're written mode 0600. Copy them off the host. To restore one into an empty database:

```sh
docker compose -f deploy/docker-compose.yml stop server
docker compose -f deploy/docker-compose.yml exec -T db \
  pg_restore -U rmm -d rmm --clean --if-exists < deploy/backups/rmm-20260101T030000Z.dump
docker compose -f deploy/docker-compose.yml start server
```

**Installing an agent**

In the dashboard, open Clients & Sites → Enroll agents. The dialog has download buttons for the
agent, and the install commands it generates download the binary themselves (the enrollment
token authorizes the download), so one pasted command does everything. The server image ships
a static Linux x86_64 binary and a Windows x64 binary in `RMM_AGENT_DIR`. To install by hand:

For Linux fleets managed with configuration management, **Create Linux package** in the same
dialog builds a `.deb` and an `.rpm` with the server URL and a dedicated token baked in. Installing
the package enrolls the machine and starts the service. Reinstalling or upgrading keeps the
existing enrollment. Anyone holding the package can enroll machines into that site, so its token
always has an expiry and a use limit (30 days and 50 uses unless you set others). Revoke the token
once the rollout is done.

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
| `RMM_METRICS_RETENTION_DAYS` | `30` | Metric history kept |
| `RMM_JOB_QUEUE_DAYS` | `7` | Jobs queued for an offline agent expire after this |
| `RMM_SESSION_IDLE_HOURS` | `12` | Dashboard sessions unused this long are signed out (sessions last 7 days at most). Admins can override it under Company settings |
| `RMM_TRUSTED_PROXIES` | empty | Reverse proxies whose `X-Forwarded-For` gives the client IP (for rate limiting and the audit log): comma-separated addresses/CIDRs, or `private` for loopback + RFC 1918 + IPv6 ULA. The bundled compose stack sets `private` for Caddy |

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
   **Update agents automatically** under Company settings to offer it whenever an agent connects.

The agent checks that the version is newer than its own, downloads it over its socket, and
verifies the checksum and signature. It then waits for running jobs to finish (at most 30 minutes)
and hands over to a watchdog: a copy of the old binary, run outside the service (a transient
systemd unit, or a detached process on Windows). The watchdog swaps the binaries and restarts the
service. If the new version hasn't reconnected within 120 s, it restores the old binary and the
agent reports `rolled_back`. Automatic updates don't retry a version that failed on that agent.
Watchdog logs: `journalctl -u 'rmm-agent-update-*'` on Linux, `C:\ProgramData\RMM\logs\update.log`
on Windows.

Updates need the agent running as a service (systemd or the Windows service). Agents installed
from a `.deb`/`.rpm` update in place, and a later package upgrade replaces the binary again.

See [docs/ROADMAP.md](docs/ROADMAP.md) for what's next: patch management, remote desktop, alerting, and more.
