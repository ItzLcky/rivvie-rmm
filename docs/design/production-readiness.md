# Production readiness

Design record for the rest of roadmap block 2 ("Before the first real customer"). Written 2026-11-15.

## Why this is next

Every feature block that can be built without outside help is built. What is left before a paying customer is evidence: that main is green, that the server's limits are known, that an operator can see what it is doing, and that an upgrade does not lose data. None of this needs a Windows lab or an outside reviewer, so it can be done now, and the load test and metrics decide whether horizontal scaling (block 7) is urgent.

Block 1 (Windows on real hosts) stays first in priority, but it waits on real machines. The outside security review waits on a reviewer.

## What done means

- CI on main is green, and stays green for the reasons below rather than by retrying.
- Ticket and portal attachments up to a configurable size work without the server holding a whole file in memory.
- An operator can scrape `/metrics` and read JSON logs.
- A report in `docs/research/` gives measured numbers for 1,000 and 10,000 simulated agents on named hardware, and says what gives out first.
- CI upgrades a database made by the previous release and runs the e2e suite on it. The README says how to back up, upgrade and roll back.

## Milestones

Do them in this order. Milestone 3 reads the metrics from milestone 2.

### 0. Green main

Two jobs failed on `ab72ebc` (run 43320795121):

- **`e2e`**: `crates/rmm-server/tests/e2e.rs:3355`. `GET /reports/qbr/{client}?from=&to=` answered `application/json` where the test expects `application/pdf`, so the handler in `crates/rmm-server/src/api/reports.rs` returned an error. Everything before it passed. The cause is not known. The test computes its range from the current date, so it may fail only on some days or only on a fresh CI database; reproduce it before changing anything, and make the test print the response body when the content type is wrong.
- **`e2e-windows`**: the test step passed, then the job ran to 50 minutes and failed. The post-job steps (rust-cache save, checkout cleanup) never finished. A process the test left behind (the installed agent service, the server, or something holding files under `target/`) is the likely reason, but that is a guess. Give the job a `timeout-minutes`, and stop whatever the test started in a step that runs `if: always()`.

The Windows job cannot be run locally. Say in the final report that its fix is unverified until the next push.

### 1. Attachments over 8 MB

Today every route except agent file upload sits under one 8 MB `RequestBodyLimitLayer` (`api/mod.rs`), and `Storage::put` / `Storage::get` take and return a whole `Vec<u8>` (`storage.rs`).

- A limit setting, `RMM_ATTACHMENT_MAX_MB`, default 100. It applies to one file. The three upload routes (`POST /tickets/{id}/attachments`, portal new ticket, portal reply) get their own body limit; everything else keeps 8 MB.
- Storage gets streaming write and read. Local: write beside the target and rename, as `put` does now. S3: multipart upload for anything over one part, aborted on failure so no parts are left billed. Server memory must not grow with file size, for upload and for download. The SHA-256 and size are computed while streaming.
- Downloads stream, and support `Range` if that is cheap with the storage layer; skip it if not.
- Over the limit returns 413 with a message naming the limit, and the web UI checks size before sending and shows the same message. The technician ticket page and the portal both need it.
- Outbound email: `email.rs` already caps what a reply attaches ("up to a total that mail servers accept"). Check that a file over that cap becomes a link the recipient can open (portal for contacts) and is never read into memory to find out it is too big.
- Inbound mail attachments stay as they are: a mail message is already bounded by the mail server.

Tests: e2e uploads a file larger than 8 MB through both routes and reads it back by hash; one over the limit gets 413; local and S3 paths are both covered (the S3 code has an existing stand-in or unit tests, follow whichever is there).

### 2. Observability

- `GET /metrics` in Prometheus text format, outside `/api`. It is off unless `RMM_METRICS_TOKEN` is set, and then requires `Authorization: Bearer <token>` compared in constant time. Without the variable the route answers 404.
- Metrics, at least: connected agents; agent messages received by type; hub send queue depth and dropped sends; SSE subscribers and lagged events; notification outbox backlog and oldest age; alert evaluation duration; scheduler tick duration; HTTP requests by method, route template and status class with a duration histogram; database pool size, idle and acquire wait; open shell and desktop sessions; process RSS and CPU seconds; build version.
- Labels must have bounded cardinality: the matched route template, never the raw path; no agent, client, user or ticket ids anywhere.
- `RMM_LOG_FORMAT=json` switches the server's logs to one JSON object per line. Text stays the default. Request logs carry method, route template, status, duration and a request id; they never carry query strings (portal one-time links and CSAT tokens travel there), bodies, or authorisation headers.
- The project keeps dependencies few (it has its own PDF and MSI writers). A small internal registry of atomics and fixed-bucket histograms is fine; a crate is fine too if it earns its place. Either way the exposition format must parse with a real Prometheus parser in a test.
- Docs: a README section with the variables, a sample scrape config, and the handful of alerts worth having (agents dropping, outbox backlog growing, alert evaluation slower than its interval, pool exhausted). Add both variables to the compose files as commented examples.

### 3. Load test

A new workspace crate, `rmm-loadgen`, that speaks the real protocol through `rmm-proto` rather than driving real agent processes.

- It enrolls N agents across a spread of clients and sites, holds their WebSockets open, and sends what a real agent sends at the real intervals: heartbeats, metrics, inventory, service lists, patch scans, security state, job output and results. Read `crates/rmm-agent/src/conn.rs` for the actual cadence and message sizes rather than assuming them. It also opens SSE dashboard clients and runs a mix of API reads (agents list, an agent page, alerts, search), and dispatches bulk jobs.
- Options for agent count, ramp rate, duration, and a time-compression factor so a day of metrics can be written in minutes for the storage figure.
- It reports connect success and time, message round-trip latency, API latency percentiles, and dropped connections, and samples the server's `/metrics` and Postgres (`pg_database_size`, largest tables, row counts) during the run.
- Run it for real at 1,000 and 10,000 agents against a release build of the server and a Postgres container on this machine (24 cores, 62 GB). Raise file-descriptor limits as needed. Write `docs/research/load-test-2026-11.md`: hardware, versions, method, a table of results (server CPU and memory, Postgres size per agent per day, alert evaluation time, latencies), what gives out first and at roughly what agent count, and what to do about it.
- Every number in the report is measured. If 10,000 cannot be reached, report the highest count that ran, why it stopped there, and whether the limit was the server, Postgres or the generator. Do not extrapolate a figure and present it as a result.
- Fix what is cheap and clearly wrong (a missing index, an N+1 query, an unbounded queue) and re-measure. Anything larger goes in the report and the roadmap, not in this block.
- CI: a short smoke run (about 200 agents for a minute) in the `e2e` job so the generator keeps working. The full runs are manual.

### 4. Upgrade path

- A CI job, `upgrade`, that builds a database with the previous release's own code and data in it, then starts the current server on that database and runs the e2e suite against it. The previous release is the newest `v*` tag (today `v0.1.1`, which stops at migration `0013`); the server image for each tag is on GHCR (`.github/workflows/image.yml`), or the tag can be built from source in the job. The database must hold real rows made through the old release (an admin, a client and site, an enrolled agent with metrics, a ticket), not just an empty schema, and after the upgrade those rows must still read back through the API.
- The e2e harness creates its own scratch database today. Give it a way to start from an existing one (a template database, or a variable naming the database to use).
- Editing a migration that has shipped in a tag must fail CI. sqlx's checksums already refuse it at startup; confirm the job would catch it and say how you confirmed it.
- README: backup, upgrade, verify, roll back. Migrations only go forward, so rolling back is restoring the dump taken before the upgrade and starting the old image tag. Say so, and say that `RMM_DATA_KEY` has to match the dump.
- If the upgrade from `v0.1.1` fails, that is a finding: fix the migration path if it can be fixed without rewriting shipped migrations, and report it either way.

## Not in this block

Horizontal scaling, TimescaleDB, tracing with OpenTelemetry, a Grafana dashboard, chunked resumable uploads, and the outside security review.
