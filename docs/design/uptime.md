# Uptime monitors

An uptime monitor checks something a client depends on, on a schedule: a website answers with the right status (and a keyword), a TCP port accepts connections, a host answers ping, a server's TLS certificate is far enough from expiry, a DNS name resolves to what it should. Built in two steps of the [parity plan](parity-plan.md): C1a, checks run **from an agent** on the client's network; C1b, checks run **by the server** for things on the public internet, which needed alerts without an agent.

## Who checks

Each monitor belongs to a client and site. With `runner: "agent"` it is run by the agent it names (any agent of the client), or, when it names none, by the site's **designated agent** (Network → Settings, the same agent that does discovery and SNMP). Changing the designated agent moves those monitors with it. Only agents that list the `checks` capability get monitors; older agents are left alone, and their monitors read "unknown".

With `runner: "server"` the server checks it itself (it names no agent). See [Checks run by the server](#checks-run-by-the-server).

## The check runner

`crates/rmm-checks` is a small library with no HTTP framework, shared by the agent and (from C1b) the server:

| Module | What |
|---|---|
| `ping` | ICMP echo. Linux and macOS: an unprivileged ICMP datagram socket (Linux needs the agent's group in `net.ipv4.ping_group_range`, or root). Windows: `IcmpSendEcho`, IPv4 only. The discovery sweep moved here from the agent. |
| `tcp` | Connect, trying each resolved address. |
| `http` | HTTP/1.1 GET or HEAD over `tokio-rustls`, `Connection: close`, at most 256 KiB read and 5 redirects followed. Status line, headers and chunked bodies are parsed here (unit-tested). URLs with a user name or password are refused. |
| `tls` | A handshake whose verifier records the certificate and whether the machine's roots trust it, and never rejects (an expired or self-signed certificate is what a certificate monitor wants to see). Handshake signatures are still checked. |
| `x509` | `notBefore`, `notAfter`, subject, issuer and SANs read with `rmm-snmp`'s BER reader. No `x509-parser`. |
| `dns` | A, AAAA, CNAME, MX, TXT against the system's resolvers or a named server; PTR and mDNS for discovery (moved from the agent). |
| `addr` | Address classes (loopback, private, link-local, cloud metadata, reserved) and the `public_only` guard server-run checks use. Every check that connects takes a guard and applies it after resolution and on every redirect (and to a named DNS server); the agent allows everything, reaching private space is its purpose. |
| `run` | One run of one `CheckSpec` with a guard: what the agent and the server both call (backup checks stay in the agent). |

Nothing returns a response body: only status, latency, "keyword found" and certificate fields. The body is read only to look for the keyword.

## Protocol

`rmm-proto/src/checks.rs`, capability `checks`:

- `ServerMsg::Checks { checks: Vec<CheckSpec>, run_now: Vec<Uuid> }`: the complete set, replacing the previous one. Pushed on connect, when a monitor is created, changed or deleted, when a policy changes (backup checks), and when a site's designated agent changes. `run_now` ("check now") is an addition to the plan: checks listed there run at once whatever their schedule. It is `#[serde(default)]`.
- `CheckSpec { id, interval_secs (30-86400), timeout_secs, kind }`; `kind` is `Ping`, `Tcp`, `Http`, `Tls`, `Dns` or `Backup` ([backups](backups.md)).
- `AgentMsg::CheckResults { results: Vec<CheckResult { check_id, at, ok, latency_ms, value, message, data }> }`. `value` is a number the check measures (HTTP status, certificate days left). `data` is typed (`CheckData::Cert` or `CheckData::Backups`) rather than free JSON, so it round-trips through MessagePack without `serde_json` in the protocol crate.

The agent (`src/checks/mod.rs`) keeps nothing across restarts. It runs at most 200 checks, 16 at a time, never two runs of one check at once, first runs spread over a few seconds. Results go in a batch every 30 seconds, and at once when a check's outcome flips (or it reports for the first time). While disconnected only each check's latest result is kept.

## Data

Migration `0040_uptime.sql`:

- `uptime_monitors`: the monitor, its `config` (per kind, normalised by the server), `runner` (`agent` or `server`), `agent_id` (NULL: the designated agent; always NULL for `server`), interval and timeout, and its current `state` (`up`/`down`/`unknown`), `state_since`, `fail_count` (consecutive failures), the last result, `cert_not_after` and the certificate's fields.
- `uptime_results (monitor_id, ts, ok, ms, message)`, kept `RMM_METRICS_RAW_DAYS`; `uptime_hourly`, written by the housekeeping loop like the agent and network rollups, kept `RMM_METRICS_RETENTION_DAYS`.
- `alerts.monitor_id`; `refresh_agent_alerts` leaves monitor alerts out of the runner's health, as `0033` did for network devices; the SIEM alert event names the monitor.
- Migration `0041_alerts_without_agent.sql` (C1b): `alerts.client_id NOT NULL` (backfilled from agent → site; the insert trigger fills it in from the agent when a caller doesn't), `alerts.agent_id` nullable, a unique open key on `(policy_id, client_id, key)` for alerts without an agent, `alert_muted(agent, client, monitor, at)` (an agentless alert is held back by its client's mutes and its monitor's site's), and the SIEM alert event joining the alert's client and its agent with `LEFT JOIN`.

The server takes an agent's timestamp only if it is within the last 24 hours; otherwise its own.

## State and alerts

A result moves the monitor: passed → `up`, `fail_count` 0; failed → `down`, `fail_count` + 1. A monitor nobody is checking becomes `unknown` (checked every `RMM_ALERT_EVAL_SECS`, at most every minute): its runner is offline, can't run checks, there is none, or it hasn't reported for three intervals and a half minute (for a server-run monitor only the last: the server was down). Switching a monitor off makes it unknown and closes its alerts quietly.

Alert kind `uptime`, an ordinary alert item in the **runner agent's** policy set (the `net_*` precedent): params `{failures: 2, kinds: [], cert_days: 14, latency_ms: null}`.

| Key | Opens when | Clears when |
|---|---|---|
| `mon:<id>` | down for `failures` checks in a row | the monitor is up |
| `mon:<id>:cert` | the certificate expires within `cert_days` (0: off) | a later certificate is further out |
| `mon:<id>:latency` | `failures` passing checks in a row slower than `latency_ms` | a check is fast again |

`unknown` neither opens nor clears. Alerts opened under a previous runner close when the monitor moves (between agents, or between an agent and the server). `uptime` isn't in the automations' `ALERT_KINDS`, and an item's "run a script" doesn't run for monitor alerts: the runner is the wrong machine.

For a monitor the server runs, the items are the enabled `uptime` items **defined in All devices** whose limit (client, site) covers the monitor's client and site, with their own config (overrides in sets below apply to agents, and there is none). Its alerts have no agent: `agent_id` is NULL and `client_id` is the monitor's client. They count against nobody's health, notify the item's channels, file tickets (with the monitor's site, no device linked), page on-call, push and reach webhooks and the SIEM like any other alert; when an item stops applying (disabled, deleted, limit changed) its open alerts close quietly.

## Checks run by the server

`uptime::run` starts a second loop that every two seconds runs the server's monitors that are due (never checked, or last checked an interval ago), at most 16 at a time and never two runs of one monitor at once, with `rmm_checks::run`. "Check now" and saving a monitor run it at once. A result is stamped when the check started and stored like an agent's.

SSRF rules:

- After the name resolves, and again on every redirect, an address that is loopback, private (RFC 1918, CGNAT 100.64/10, IPv6 ULA), link-local, cloud metadata (169.254.169.254, fd00:ec2::254, 100.100.100.200) or otherwise reserved is refused, unless `RMM_UPTIME_ALLOW_PRIVATE=1`. The refusal is the check's result ("127.0.0.1 is a loopback address, which checks run by the server may not reach"): the monitor goes down, as for any failure.
- A literal address of those kinds (host, URL host, DNS server) is refused when the monitor is saved, so the form says so at once.
- A named DNS server goes past the same guard; lookups through the system's resolvers don't connect to the target.
- URLs with a user name or password are refused (as for agents); nothing returns a body.

ICMP from the server needs the server's group in `net.ipv4.ping_group_range` (or root), like the agent on Linux.

## API and UI

`api/uptime.rs`: `GET|POST /uptime/monitors`, `GET|PUT|DELETE /uptime/monitors/{id}`, `POST /uptime/monitors/{id}/check`, `GET /uptime/monitors/{id}/results?from&to` (about 500 points; raw within 48 hours, hourly beyond), `GET /uptime/summary`. Reads for anyone scoped to the client, changes for technicians, audited `uptime.create`, `uptime.update`, `uptime.delete`, `uptime.check`. Public API (group `network`): `listUptimeMonitors`, `getUptimeMonitor`, `getUptimeResults`. Alert rows carry `monitor_id` and `monitor_name` (and, for a server-run monitor, a null `agent_id` and `hostname`). Monitors take `runner` (`agent` or `server`). Live events: `monitor`.

Dashboard: `/uptime` (Monitoring in the sidebar, `g m`) and `/uptime/[id]` with a 90-day availability bar, response time and pass-rate charts, the certificate and the latest checks; a drawer to add or edit a monitor with the runner picker; the `Uptime monitor` kind in the alert form; an "Availability" block in the QBR (from hourly rollups).

## Limits

- No multi-step transactions, browser checks, multi-region consensus or status pages (out of scope).
- HTTP/1.1 only, no proxies; a server that speaks only HTTP/2 fails.
- ICMP on Windows (`IcmpSendEcho`) is compile-checked only; see [windows-testing.md](windows-testing.md).
- Server-run monitors are checked from one place (no multi-region consensus); the server's own network outage reads as monitors down.
- An alert without an agent has no device to run a script or automation on.
