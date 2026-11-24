# Uptime monitors

An uptime monitor checks something a client depends on, on a schedule: a website answers with the right status (and a keyword), a TCP port accepts connections, a host answers ping, a server's TLS certificate is far enough from expiry, a DNS name resolves to what it should. Built as step C1a of the [parity plan](parity-plan.md): checks run **from an agent** on the client's network. Step C1b (checks run by the server, and alerts without an agent) comes later and reuses everything here.

## Who checks

Each monitor belongs to a client and site. It is run by the agent it names (any agent of the client), or, when it names none, by the site's **designated agent** (Network → Settings, the same agent that does discovery and SNMP). Changing the designated agent moves those monitors with it. Only agents that list the `checks` capability get monitors; older agents are left alone, and their monitors read "unknown".

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
| `addr` | Address classes (loopback, private, link-local, cloud metadata, reserved) and the `public_only` guard C1b's server-run checks will use. Every check that connects takes a guard and applies it after resolution and on every redirect; the agent allows everything, reaching private space is its purpose. |

Nothing returns a response body: only status, latency, "keyword found" and certificate fields. The body is read only to look for the keyword.

## Protocol

`rmm-proto/src/checks.rs`, capability `checks`:

- `ServerMsg::Checks { checks: Vec<CheckSpec>, run_now: Vec<Uuid> }`: the complete set, replacing the previous one. Pushed on connect, when a monitor is created, changed or deleted, when a policy changes (backup checks), and when a site's designated agent changes. `run_now` ("check now") is an addition to the plan: checks listed there run at once whatever their schedule. It is `#[serde(default)]`.
- `CheckSpec { id, interval_secs (30-86400), timeout_secs, kind }`; `kind` is `Ping`, `Tcp`, `Http`, `Tls`, `Dns` or `Backup` ([backups](backups.md)).
- `AgentMsg::CheckResults { results: Vec<CheckResult { check_id, at, ok, latency_ms, value, message, data }> }`. `value` is a number the check measures (HTTP status, certificate days left). `data` is typed (`CheckData::Cert` or `CheckData::Backups`) rather than free JSON, so it round-trips through MessagePack without `serde_json` in the protocol crate.

The agent (`src/checks/mod.rs`) keeps nothing across restarts. It runs at most 200 checks, 16 at a time, never two runs of one check at once, first runs spread over a few seconds. Results go in a batch every 30 seconds, and at once when a check's outcome flips (or it reports for the first time). While disconnected only each check's latest result is kept.

## Data

Migration `0040_uptime.sql`:

- `uptime_monitors`: the monitor, its `config` (per kind, normalised by the server), `runner` (`agent`; `server` reserved for C1b), `agent_id` (NULL: the designated agent), interval and timeout, and its current `state` (`up`/`down`/`unknown`), `state_since`, `fail_count` (consecutive failures), the last result, `cert_not_after` and the certificate's fields.
- `uptime_results (monitor_id, ts, ok, ms, message)`, kept `RMM_METRICS_RAW_DAYS`; `uptime_hourly`, written by the housekeeping loop like the agent and network rollups, kept `RMM_METRICS_RETENTION_DAYS`.
- `alerts.monitor_id`; `refresh_agent_alerts` leaves monitor alerts out of the runner's health, as `0033` did for network devices; the SIEM alert event names the monitor.

The server takes an agent's timestamp only if it is within the last 24 hours; otherwise its own.

## State and alerts

A result moves the monitor: passed → `up`, `fail_count` 0; failed → `down`, `fail_count` + 1. A monitor nobody is checking becomes `unknown` (checked every `RMM_ALERT_EVAL_SECS`, at most every minute): its runner is offline, can't run checks, there is none, or it hasn't reported for three intervals and a half minute. Switching a monitor off makes it unknown and closes its alerts quietly.

Alert kind `uptime`, an ordinary alert item in the **runner agent's** policy set (the `net_*` precedent): params `{failures: 2, kinds: [], cert_days: 14, latency_ms: null}`.

| Key | Opens when | Clears when |
|---|---|---|
| `mon:<id>` | down for `failures` checks in a row | the monitor is up |
| `mon:<id>:cert` | the certificate expires within `cert_days` (0: off) | a later certificate is further out |
| `mon:<id>:latency` | `failures` passing checks in a row slower than `latency_ms` | a check is fast again |

`unknown` neither opens nor clears. Alerts opened under a previous runner close when the monitor moves. `uptime` isn't in the automations' `ALERT_KINDS`, and an item's "run a script" doesn't run for monitor alerts: the runner is the wrong machine.

## API and UI

`api/uptime.rs`: `GET|POST /uptime/monitors`, `GET|PUT|DELETE /uptime/monitors/{id}`, `POST /uptime/monitors/{id}/check`, `GET /uptime/monitors/{id}/results?from&to` (about 500 points; raw within 48 hours, hourly beyond), `GET /uptime/summary`. Reads for anyone scoped to the client, changes for technicians, audited `uptime.create`, `uptime.update`, `uptime.delete`, `uptime.check`. Public API (group `network`): `listUptimeMonitors`, `getUptimeMonitor`, `getUptimeResults`. Alert rows carry `monitor_id` and `monitor_name`. Live events: `monitor`.

Dashboard: `/uptime` (Monitoring in the sidebar, `g m`) and `/uptime/[id]` with a 90-day availability bar, response time and pass-rate charts, the certificate and the latest checks; a drawer to add or edit a monitor with the runner picker; the `Uptime monitor` kind in the alert form; an "Availability" block in the QBR (from hourly rollups).

## Limits

- No multi-step transactions, browser checks, multi-region consensus or status pages (out of scope).
- HTTP/1.1 only, no proxies; a server that speaks only HTTP/2 fails.
- ICMP on Windows (`IcmpSendEcho`) is compile-checked only; see [windows-testing.md](windows-testing.md).
- Server-run monitors (C1b) and the SSRF rules for them (`RMM_UPTIME_ALLOW_PRIVATE`) are not built yet; `runner: "server"` is refused.
