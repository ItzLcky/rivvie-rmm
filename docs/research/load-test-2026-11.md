# Load test, November 2026

How many agents one server holds, what it costs, and what gives out first. Run 2026-11-15
with `crates/rmm-loadgen` against a release build of `rmm-server` (block 2, milestone 3 of
[design/production-readiness.md](../design/production-readiness.md)).

Every number below comes from a run on the machine described here. Where a figure is
calculated from measured ones (storage over a retention period), it says so.

## Summary

- **10,000 agents ran for 10 minutes with every session up and none dropped**, on one server
  process using about a quarter of a core and 0.94–1.02 GB of memory. Holding agents
  connected is not the problem. Taking in their data costs little on its own: with no
  dashboard traffic, Postgres averaged 0.19 cores at 10,000 agents.
- **What gives out first is Postgres, under dashboard reads.** Two queries scan every agent
  whenever they run: the global search (the agent part reads each agent's inventory JSON for
  IP addresses and users, ~0.8 s at 10,000 agents with nothing else running) and the
  dashboard's per-agent health (~0.27 s at 10,000 after the fix below; it was ~0.6 s). An open
  dashboard refetches on every alert, job and online/offline event, so a handful of open
  dashboards on a busy 10,000-agent fleet keeps several Postgres cores busy. At 10,000 agents
  with 10 page requests a second and 20 open dashboards, after the fixes: page reads (agent
  list, agent page, metrics, alerts) p50 18 ms and p95 349 ms, dashboard p50 280 ms / p95 2.9 s,
  search p50 842 ms / p95 3.3 s. Usable, but the next customer size up needs these two fixed.
- **Second: the database disk's fsync rate.** Here Postgres's volume was btrfs on a SATA SSD
  that manages ~155 `fdatasync`/s. Before heartbeats committed asynchronously, every pooled
  connection sat in `COMMIT` waiting for the WAL flush at 10,000 agents, and everything else
  (page requests, alert evaluation) queued behind them. Job results still commit
  synchronously, which is why a 500-agent bulk run's results took up to ~4.5 s (p95) to be
  acknowledged. A server-class NVMe drive with power-loss protection would move this a long
  way; it should be in the hardware advice.
- **Horizontal scaling is not urgent.** The server process was never the limit, and splitting
  agents across nodes would not help the two problems above, which are in the database.
- **Storage: 564 KB per agent per day of raw metrics** (measured), about 4.5 MB per agent at
  the default retention (calculated), so ~45 GB of Postgres for 10,000 agents. Raw samples
  kept for 7 days are almost all of it.
- **20,000 agents connected and stayed connected, but the database fell behind** for ~3 minutes
  after they came on (19,000 of them new): 94 requests failed with pool timeouts and alert
  passes took up to 56 s of their 60 s interval, before it settled. So the limit on this
  machine is somewhere between 10,000 and 20,000 agents, set by Postgres
  ([details](#20000-agents)).

Fixed during the test, each re-measured (details under [Fixes](#fixes-made-and-re-measured)):
per-connection WebSocket read buffers (server memory at 10,000 agents 1.76 → 1.02 GB), bulk
job creation one query per agent (500 jobs 10.6 s → 0.05 s), the dashboard computing health
three times per agent (0.61 → 0.27 s uncontended), and heartbeats waiting for an fsync each
(pool acquire wait 849 → 22 ms, Postgres 7.1 → 2.5 cores, page-read p95 4.8 s → 0.35 s).

**Update 2026-11-22:** the search and dashboard-health scans described above are fixed by
stored columns (migration 0026); see [Stored columns for search and
health](#stored-columns-for-search-and-health) for the re-measurement. The figures in the rest of
this document are from before that change.

## Hardware and versions

| | |
|---|---|
| CPU | AMD Ryzen 9 5900X, 12 cores / 24 threads, up to 4.95 GHz |
| Memory | 62 GiB (64 GB) |
| Disk (Postgres data) | SanDisk SDSSDA240G (SATA SSD, 240 GB, also the system disk), btrfs; Docker volume. `pg_test_fsync`: `fdatasync` 155 ops/s (6.4 ms), `fsync` 384 ops/s |
| OS | CachyOS Linux, kernel 7.3.0-4-cachyos; Docker 29.9.2 |
| Postgres | 17.11 (`postgres:17-alpine`), default configuration (`shared_buffers` 128 MB, `max_connections` 100, `synchronous_commit` on), `pg_stat_statements` loaded from the second 10,000 run on |
| Server | `rmm-server` from this branch (on `ab72ebc`), `cargo build --release` with the workspace profile (`opt-level = "z"`, fat LTO), glibc, Rust 1.99.1. Pool of 32 connections (hard-coded). Defaults otherwise: heartbeat 30 s, inventory 6 h, alert evaluation every 60 s |
| Generator | `rmm-loadgen` (release build) on the same machine, talking to `127.0.0.1` |

The shipped Docker image is built on Alpine (musl), whose allocator is slower under many
threads than glibc's. It was not measured; expect the server process to need somewhat more CPU
there. The server process stayed far below its limits here, so this shouldn't change the
conclusions.

## Method

`rmm-loadgen` enrolls simulated agents with real enrollment tokens and speaks the agent
protocol through `rmm-proto` over real WebSockets, one per agent. What each agent sends, and
when, follows `crates/rmm-agent/src/conn.rs` and the modules it starts:

| On connect | Then |
|---|---|
| Heartbeat and inventory at once (the agent's periodic tasks fire immediately), another inventory when the server asks, the service list, the protection state | Heartbeat every `heartbeat_secs` from `AuthOk` (30 s); inventory every `inventory_secs` (6 h); service list on change (here once an hour per agent: real agents send it only when a service changes, so this is generous); protection state hourly (the agent's keepalive) |

It answers what the server asks for: patch scans (after 5–30 s, 12 updates), scripts (output,
then the result, kept until the server's `JobAck`), service lists, protection refreshes. It
announces the `patch`, `security` and `tools` capabilities, not the sensor or remote desktop,
so no sensor content was pushed. 70% report as Windows, 30% as Linux; ~2% report CPU over 90%
so the CPU policy has alerts to open. Four MSP-wide alert policies (offline, CPU, memory,
disk) were active.

Encoded message sizes: heartbeat 372 B, inventory 29.0 KB (300 software entries), service
list 24.0 KB (250 services), protection state 379 B, patch scan result 1.9 KB.

Alongside the agents it keeps dashboards open (`/api/events`, 10 at 1,000 agents, 20 at
10,000), makes page requests at a steady rate (5/s at 1,000, 10/s at 10,000; in turn the
agents list, one agent, its 24-hour metrics, the alert list, search, and the dashboard), and
every 120 s runs a script on 500 agents. It samples the server's `/metrics` every 15 s, the
Postgres container's CPU and memory (`docker stats`) and the database size, and reports
latency percentiles from its own timings:

- **connect**: WebSocket open to `AuthOk`;
- **job dispatch**: from the bulk `POST /api/jobs` being sent to the script reaching the agent;
- **result ack**: from the agent sending a job result to receiving the server's `JobAck`
  (the one round trip in the protocol where the server stores something and answers);
- **page reads**: the median of the per-endpoint percentiles for the agents list, agent page,
  agent metrics and alert list.

Each run ramps agents in at a fixed rate (100/s for 1,000, 200/s for 10,000), waits for all to
be online, then holds for the duration while the dashboards, page requests and bulk runs go
on. "Hold" figures are means over the hold, from 30 s after the ramp.

Caveats:

- Generator and server share the machine. The generator used at most 0.3 cores (0.06 during
  the 10,000-agent holds), so it was never the limit, but they did share the CPU and disk.
- The 10,000-agent runs reused one database, so later runs had more history in it (461,000
  metric rows by the third run against 242,000 for the second). The 1,000-agent runs after
  the fixes used that database trimmed to its first 1,000 agents.
- Simulated agents send fixed-size payloads; real inventories vary from a few dozen software
  entries to thousands.
- Holds were 10 minutes. Anything slower (bloat, autovacuum on a week of metrics, the hourly
  rollup over a full table, retention deletes) did not show up and wants a longer run.

## Results

`a` is before any fix, `b` after the first three fixes (buffers, bulk jobs, dashboard), `c`
after all four (also heartbeats committing asynchronously). "noreads" is 10,000 agents after
the first three fixes with dashboards open and bulk runs but no page requests, to separate
holding agents from serving the dashboard.

| | 1,000 a | 1,000 c | 10,000 a | 10,000 b | 10,000 c | 10,000 noreads |
|---|---|---|---|---|---|---|
| Online after ramp / dropped during hold | 1,000 / 0 | 1,000 / 0 | 10,000 / 0 | 10,000 / 0 | 10,000 / 0 | 10,000 / 0 |
| Ramp (s) | 10.0 | 10.5 | 54.3 | 53.0 | 52.5 | 53.5 |
| Connect p50 / p95 (ms) | 13 / 428 | 37 / 1,114 | 888 / 3,411 | 1,037 / 5,246 | 821 / 3,709 | 886 / 4,267 |
| Server CPU, hold (cores) | 0.02 | 0.02 | 0.27 | 0.24 | 0.24 | 0.25 |
| Server CPU, ramp peak (cores) | 0.29 | 0.29 | 1.25 | 1.06 | 1.03 | 0.93 |
| Server RSS (MB, max) | 261 | 111 ¹ | 1,756 | 1,024 | 941 | 1,133 |
| Postgres CPU, hold mean / max (cores) | 0.30 / 1.20 | 0.15 / 0.75 | 6.36 / 19.94 | 7.09 / 18.48 | 2.46 / 6.38 | 0.19 / 0.61 |
| Agent messages/s, hold | 40 | 40 | 342 | 347 | 343 | 350 |
| Pool idle, mean / min (of 32) | 28.4 / 1 | 30.1 / 0 | 10.4 / 0 | 8.7 / 0 | 26.2 / 0 | 15.4 / 0 |
| Pool acquire wait, mean of 5 s probes (ms) | 4 | 1 | 722 | 849 | 22 | 529 |
| Alert evaluation, median / max per pass (ms) | 35 / 50 | 51 / 56 | 364 / 2,822 | 393 / 38,517 ² | 328 / 3,976 | 538 / 4,988 |
| Page reads p50 / p95 / p99 (ms) | 4 / 5 / 1,004 | 6 / 7 / 8 | 302 / 3,388 / 4,917 | 574 / 4,812 / 8,395 | 18 / 349 / 3,194 | – |
| Dashboard p50 / p95 (ms) | 62 / 783 | 46 / 55 | 1,991 / 6,593 | 1,516 / 8,543 | 280 / 2,886 | – |
| Search p50 / p95 (ms) | 79 / 89 | 80 / 90 | 2,101 / 5,516 | 2,366 / 8,149 | 842 / 3,347 | – |
| Bulk run on 500: create p50 (ms) | 4,900 | 42 | 10,558 | 911 | 48 | 49 |
| Job dispatch p50 / p95 (ms) | 1,373 / 4,697 | 34 / 553 | 6,427 / 11,647 | 902 / 1,985 | 42 / 771 | 42 / 1,999 |
| Result ack p50 / p95 (ms) | 6 / 2,273 | 6 / 4,866 | 46 / 3,334 | 8 / 17,097 | 8 / 4,549 | 7 / 4,126 |
| HTTP 5xx, API errors, SSE streams dropped | 0 | 0 | 0 | 0 | 0 | 0 |

¹ From a separate 3-minute 1,000-agent run on a freshly started server; in `1,000 c` the
process had just held 10,000 agents and kept that memory (978 MB).
² The first evaluation after the ramp, when 10,000 agents' connect-time writes were still
queued; the rest of that hold's passes were 196–2,961 ms.

The alert evaluation interval is 60 s, so even the slowest pass after the fixes (4.0 s) left
plenty of room. Process threads stayed at 25 and open file descriptors at ~10,100 (one per
agent) at 10,000.

Uncontended (no agents connected, the 10,000-agent database), each request timed five times:

| | Before | After |
|---|---|---|
| `GET /api/search?q=…` | 799 ms | 794 ms |
| `GET /api/dashboard` | 610 ms | 265 ms |
| `GET /api/agents?limit=50` | 28 ms | 30 ms |
| `GET /api/agents/{id}` | 5 ms | 3 ms |
| `GET /api/alerts?limit=50` | 6 ms | 33 ms ³ |

³ More alerts by then (the hot agents had opened CPU alerts during the intervening runs).

## 20,000 agents

Beyond what the spec asked for, to find where it breaks: after all four fixes, 20,000 agents
(19,000 of them enrolling for the first time), ramped at 200/s and held for 5 minutes with
the same page-request, dashboard and bulk mix as the 10,000 runs (10/s, 20, 500 every 120 s).

All 20,000 connected (ramp 102 s) and none dropped. But for about three minutes after the
ramp the database couldn't keep up: the new agents' first inventories (two each, ~29 KB),
service lists, protection states and patch scan results (12 updates each, ~18,700 scans) came
in on top of the heartbeats. In that window Postgres ran at 16–21 cores, the pool had no idle
connection in any sample, the acquire probe waited 3–5 s, and **94 requests failed with 500**,
every one `pool timed out while waiting for an open connection` (the 10 s acquire timeout).
Alert evaluation passes took 38 s, 56 s and 36 s against a 60 s interval. Once that backlog
cleared (from ~255 s), it settled: Postgres 3–5 cores, ~25 idle connections, alert passes
0.5–0.8 s, server process 0.57 cores and 1.95 GB.

| | 10,000 c | 20,000 (whole run) |
|---|---|---|
| Online after ramp / dropped | 10,000 / 0 | 20,000 / 0 |
| Server CPU, hold / RSS max | 0.24 cores / 941 MB | 0.63 cores / 1,950 MB |
| Postgres CPU, hold mean / max | 2.46 / 6.38 | 9.61 / 21.31 |
| Agent messages/s, hold | 343 | 771 |
| Alert evaluation, median / max (ms) | 328 / 3,976 | 18,423 / 55,817 |
| Page reads p50 / p95 (ms) | 18 / 349 | 1,375 / 16,783 |
| Dashboard p50 / p95 (ms) | 280 / 2,886 | 4,468 / 57,817 |
| Search p50 / p95 (ms) | 842 / 3,347 | 6,743 / 36,925 |
| Bulk run on 500: create p50 (ms) | 48 | 13,051 |
| HTTP 5xx | 0 | 94 |

The latency percentiles cover the whole run, so they mix the backlog with the calm after it.
The two runs differ in more than size: 10,000 c had no newly enrolled agents (every agent had
already been scanned), while here 19,000 were new. A server restart with 20,000 agents would
bring back most of that burst (reconnecting agents send inventory, services and protection
state again; patch scans only if the last one is over 12 hours old). So **somewhere between
10,000 and 20,000 agents** this machine stops absorbing a mass (re)connect without errors, with
Postgres CPU and the 32-connection pool the limit, not the server process or the generator
(0.12 cores). Where exactly in between wasn't measured.

## Storage

Measured with a fresh database: 200 agents with every agent-side interval divided by 60,
held for 1,441 s, so each agent sent one day's messages (a heartbeat every 0.5 s instead of
30 s; 2,887 heartbeats each, 2,880 expected). The server's own timers ran in real time, so
hourly rollups are not part of this figure.

| | Measured |
|---|---|
| `agent_metrics` (raw heartbeat samples) | 577,480 rows, 112.8 MB (58.6 MB table, 54.2 MB in its two indexes): **564 KB per agent per day**, 195 bytes per sample |
| `agents` (the agent row: last metrics, inventory, service list) | 6.8 MB for 200 agents: 34 KB each, rewritten rather than grown |
| `patches`, `security_products` | 0.95 MB and 0.34 MB for 200 agents |
| Whole database, growth for the day | 121.4 MB: **607 KB per agent** for the first day (including the per-agent state above) |
| After `VACUUM` | 134.0 MB (no reclaimable space to speak of) |
| Hourly rollups (`agent_metrics_hourly`), bytes per row | 221 (from 1,000 rows, so ±10%) |

Calculated from those, at the default retention (`RMM_METRICS_RAW_DAYS` 7,
`RMM_METRICS_RETENTION_DAYS` 90):

| Per agent | |
|---|---|
| Raw samples, 7 days | 7 × 564 KB = 3.9 MB |
| Hourly rollups, 90 days | 90 × 24 × 221 B = 0.48 MB |
| Agent row, patches, protection state | ~0.04 MB |
| **Total** | **~4.5 MB**: ~4.5 GB at 1,000 agents, ~45 GB at 10,000 |

Not included: job output (capped at 1 MB per stream per job, and kept until the schedule's
retention or forever for ad-hoc jobs), alerts, tickets, the audit log, WAL and backups. Halving
`RMM_METRICS_RAW_DAYS` roughly halves the total; charts beyond 48 hours read the rollups
anyway.

## Fixes made and re-measured

1. **WebSocket read buffers** (`agent_ws.rs`). tungstenite allocates a 128 KiB read buffer per
   connection; 8 KiB is plenty for agent messages. Server RSS at 10,000 agents: 1,756 → 1,024 MB
   (runs a → b), and 941 MB in run c. At 1,000 agents on a fresh process: 261 → 111 MB.
2. **Bulk job creation** (`api/jobs.rs`). It inserted and then claimed each job with its own
   queries, one agent after another. Now one insert for all agents and one update for the
   online ones. A 500-agent run: 10.6 s → 0.91 s (run b, with a saturated pool) → 0.05 s
   (run c); time for the script to reach the agent p50 6.4 s → 0.04 s.
3. **Dashboard health** (`api/agents.rs`). The health expression (open alerts, failed jobs,
   overdue and failed patches, the disks in `last_metrics`, per agent) was evaluated once for
   the histogram and twice more for the per-client rows. Now once, in one query. Uncontended at
   10,000 agents: 610 → 265 ms.
4. **Heartbeats commit asynchronously** (`agent_ws.rs`, `SET LOCAL synchronous_commit = off`
   for the heartbeat's transaction only). A crash can lose the last fraction of a second of
   samples; nothing else changes. `pg_stat_activity` sampled during a 10,000-agent hold before
   this showed all 31 busy connections in `COMMIT` waiting on `WALWrite`/`WalSync`. After: pool
   acquire wait 849 → 22 ms, Postgres CPU 7.1 → 2.5 cores, page-read p95 4.8 s → 0.35 s,
   dashboard p50 1.5 s → 0.28 s (runs b → c).

## Stored columns for search and health

Added 2026-11-22 (migration 0026). The two things the first test found gave out first, the
global search and the dashboard's per-request health, now read stored columns:

- **Search.** An agent's addresses and logged-in users are copied out of its inventory JSON into
  `agent_search_terms` when the inventory arrives (a trigger on `agents.inventory`). Hostname,
  OS name and those terms have `pg_trgm` GIN indexes, and `agent_search()` is a union of index
  lookups. Results are the same as before (a test compares the two on a mixed fleet,
  including `%`/`_` in the search text); the old expression also failed outright on a malformed
  inventory, the new one doesn't.
- **Health.** Each agent row stores its health rank and the inputs to it (open alerts, whether a
  critical or warning alert is open and not held back, failed jobs in 24 hours, overdue and
  failed patches, the fullest disk). Triggers on `alerts`, `jobs`, `patches` and the agent row
  itself keep them current; the rank rules are the SQL function `agent_health_rank`. The
  server's housekeeping runs `refresh_agent_health()` every five minutes for what only time
  changes (a job ageing past 24 hours, an update missing for a week) and as a safety net: 0.46 s
  of Postgres at 10,000 agents when nothing differs, and it writes only rows that differ. The
  dashboard, the agent list, its health filter and its health sort now read columns.

Cost: the migration took 4.5–5.3 s on the 10,000-agent database. The new table and four indexes
are about 22 MB at 10,000 agents (2.2 KB per agent). Per write: the inventory update went from
1.2–1.9 ms to 2.4–2.6 ms (the search terms are rewritten only if the inventory changed); a
heartbeat is unchanged (0.1–0.2 ms) and a scan's 12 new patch rows cost nothing extra. A
micro-benchmark of 3,000 scans (36,000 `patches` rows, one statement per scan) took 689 ms with
the triggers and 673 ms without them. A first version of the patches trigger recounted on every
insert and cost 3.6 ms per scan; a test that compares the stored values to the old expressions
after every kind of change caught a duplicate-id counting bug in the second version.

### Method

Same generator, server build profile and hardware as above, 10,000 agents, 240 s hold
(`--duration 240`; otherwise the command in [Reproducing](#reproducing)). The machine was shared
with other builds and test runs during this work (load average 8–37, and `/proc/pressure/io`
at 50–70% from other processes' disk writes), which wrecked the first loaded runs on the
btrfs volume (fsync stalls dropped sessions and timed out requests in both the before and the
after run). So:

- **Uncontended** figures (no agents connected, the 10,000-agent database, median of 5) are from
  the btrfs database, before binary and after binary on the same data, back to back.
- **Loaded** figures use Postgres on a tmpfs (`docker run --tmpfs /var/lib/postgresql/data`), so
  disk contention from other processes can't reach it; the server and generator still shared
  the CPU. "Burst" is a database where all 10,000 agents enrolled in that run (first inventories,
  first patch scans); "steady" is the next run on the same agents. Before = the binary at
  `28df9a1`; after = this change.

### Uncontended, 10,000 agents (ms, median of 5)

| | Before | After |
|---|---|---|
| `GET /api/search?q=<hostname prefix>` | 844 | 16 |
| `GET /api/search?q=<full hostname>` | 800 | 17 |
| `GET /api/search?q=10.0.0.` (IP prefix, matches every agent) | 424 | 43 |
| `GET /api/search?q=alice` (logged-in user, matches every agent) | 825 | 44 |
| `GET /api/search?q=lg` (two characters, no trigram to use) | 48 | 31 |
| `GET /api/agents?limit=50&q=<hostname prefix>` | 1,936 | 38 |
| `GET /api/agents?limit=50&q=10.0.0.` | 959 | 58 |
| `GET /api/dashboard` | 257 | 53 |
| `GET /api/agents?limit=50&sort=health` | 1,587 | 27 |
| `GET /api/agents?limit=50&health=unhealthy,attention` | 736 | 13 |
| `GET /api/agents?limit=50` | 27 | 27 |
| `GET /api/alerts?limit=50` | 6 | 6 |

The search and agent-list filters that match every agent still have to return and sort all
10,000 rows, which is what the 40–60 ms is. A two-character search can't use a trigram index and
reads all three of them; it is about as fast as before. (A second pair of measurements on the
tmpfs database, taken while the machine was busier, gave before/after: search by hostname prefix
1,591 → 8 ms, agent list sorted by health 3,530 → 36 ms, dashboard 909 → 93 ms.)

### Loaded, 10,000 agents, Postgres on tmpfs (ms)

| | Before, burst | After, burst | Before, steady | After, steady |
|---|---|---|---|---|
| Online after ramp / dropped | 10,000 / 0 | 10,000 / 0 | 10,000 / 0 | 10,000 / 0 |
| Agent page p50 / p95 | 5 / 16 | 4 / 36 | 17 / 70 | 4 / 7 |
| Agents list p50 / p95 | 38 / 93 | 32 / 151 | 126 / 234 | 32 / 42 |
| Alert list p50 / p95 | 4 / 16 | 4 / 35 | 21 / 66 | 6 / 10 |
| **Dashboard p50 / p95** | 240 / 2,754 | 40 / 279 | 784 / 1,123 | **47 / 63** |
| **Search p50 / p95** | 856 / 1,460 | 9 / 42 | 2,019 / 2,618 | **4 / 8** |
| Job dispatch p50 / p95 | 125 / 166 | 103 / 120 | 163 / 189 | 30 / 33 |
| Result ack p50 / p95 | 2.5 / 58 | 3 / 22 | 18 / 105 | 1 / 2 |
| Postgres CPU, hold mean (cores) | 3.45 | 0.50 | 3.80 | 0.28 |
| Pool idle, mean (of 32) | 25.3 | 29.5 | 22.8 | 30.3 |
| Alert evaluation, mean per pass (ms) | 117–394 | 111–1,881 | 595–2,060 | 285–411 |
| API errors | 0 | 0 | 0 | 0 |

The burst and steady columns of one binary were taken minutes apart under different outside
load (the second "before" run overlapped with other builds; the second "after" run did not), so
read the pairs as order-of-magnitude, not as exact ratios. The query-level numbers from
`pg_stat_statements` are less sensitive to that: in the before-steady run the search query
averaged 1,739 ms per call (427 calls) and the dashboard's health query 423 ms (406 calls); in
the after-steady run neither is in the top ten, the dashboard's health query averages 10.5 ms
and the largest remaining read is the dashboard's offline/high-disk lists (22 ms).

### What is left

- The dashboard is still ~50 ms: five queries that each read all agents (the offline list,
  OS counts, per-client health counts, the totals). A per-client rollup table would take that
  to a few ms, but it is already off the list of things that give out first.
- Searches of one or two characters, and searches that match most of the fleet, still read and
  sort every match.
- The 20,000-agent mass reconnect was not re-run: its limit (Postgres CPU and the pool during
  inventory, service and patch-scan writes) is in writes this change barely touches.

## What to do next

In order of what the test says matters:

1. **Search** (done, [see above](#stored-columns-for-search-and-health): 0.84 s → 16 ms). The agent part matched
   IP addresses and logged-in users by expanding every agent's inventory JSON. Store those in
   their own columns (or a small table) when inventory arrives, and index hostnames for
   substring search (`pg_trgm`). Needs a migration; bigger than this block.
2. **Dashboard health** (done: 0.26 s → 53 ms uncontended, and Postgres under a loaded
   dashboard 3.5–3.8 → 0.3–0.5 cores). It was ~0.27 s per call at 10,000, refetched on every
   alert, job and online/offline event by every open dashboard. Compute health when its inputs change (a
   heartbeat, an alert, a job result, a patch scan) and store it on the agent, so the
   dashboard and agent list just count. Also worth debouncing the dashboard's refetch more on
   big fleets.
3. **Hardware advice.** Put Postgres on a disk with a fast fsync (NVMe with power-loss
   protection) and not on a copy-on-write filesystem; say so in the README next to the
   capacity note. Job results, alerts and everything else still commit synchronously.
4. **Pool size.** 32 connections is hard-coded. A setting (`RMM_DB_MAX_CONNECTIONS`) is cheap,
   though with the fixes above the pool wasn't the limit in run c.
5. **Longer runs.** A 24-hour hold at 10,000 agents would show autovacuum, rollups and
   retention deletes on full tables, which 10 minutes can't.

Horizontal scaling (roadmap block 7) can wait: one node held 10,000 agents with the server
process at a quarter of a core, and the limits found are in the database, which more server
nodes would share.

## Reproducing

```sh
docker run -d --name rmm-load-pg -e POSTGRES_USER=rmm -e POSTGRES_PASSWORD=rmm -e POSTGRES_DB=rmm \
  -p 55433:5432 -v rmm-load-pgdata:/var/lib/postgresql/data postgres:17-alpine -c shared_preload_libraries=pg_stat_statements
cargo build --release -p rmm-server -p rmm-loadgen
DATABASE_URL=postgres://rmm:rmm@localhost:55433/rmm RMM_BIND=127.0.0.1:18080 RMM_PUBLIC_URL=http://127.0.0.1:18080 \
  RMM_ADMIN_EMAIL=load@example.test RMM_ADMIN_PASSWORD=load-test-password RMM_METRICS_TOKEN=load-metrics-token \
  RMM_DATA_KEY=$(openssl rand -hex 32) RMM_WEB_DIR=/tmp/load/web RMM_AGENT_DIR=/tmp/load RMM_STORAGE_DIR=/tmp/load/storage \
  target/release/rmm-server &
target/release/rmm-loadgen --server http://127.0.0.1:18080 --admin-email load@example.test --admin-password load-test-password \
  --agents 10000 --ramp 200 --duration 600 --clients 100 --sites 2 --bulk-every 120 --bulk-size 500 --sse 20 --api-rps 10 \
  --metrics-token load-metrics-token --database-url postgres://rmm:rmm@localhost:55433/rmm --pg-container rmm-load-pg \
  --state loadgen-state.json --out run.json
# Storage: a fresh database, then
#   --agents 200 --clients 10 --duration 1440 --time-compression 60 --bulk-every 0 --sse 0 --api-rps 0
```

`--state` keeps the enrolled agents' credentials (and the admin's TOTP secret) between runs.
