# Operator guide

One install path for an MSP running RMM for real: a single Docker host with the compose stack in
`deploy/`, TLS from Caddy, nightly backups, and the few secrets worth protecting. The
[README](../README.md) describes what the product does and has the detail behind several
sections here; this page puts the steps in order and links there rather than repeating it.

Contents: [Before you start](#before-you-start) · [Install](#install) · [TLS and the reverse
proxy](#tls-and-the-reverse-proxy) · [Secrets to keep safe](#secrets-to-keep-safe) · [Sizing](#sizing) ·
[Environment variable reference](#environment-variable-reference) · [Backups and
restore](#backups-and-restore) · [Monitoring](#monitoring) · [Upgrades](#upgrades) ·
[First clients and agents](#first-clients-and-agents)

## Before you start

- A Linux host with Docker (Compose v2) and ports 80 and 443 reachable from the internet (Caddy
  needs both to get a certificate), or from your agents' networks plus a name your internal CA
  can issue for.
- A DNS name for the server (`rmm.example.com`) pointing at it. Agents are given this name and
  need `https://`; plain `http://` is refused except for localhost.
- For anything beyond a trial, a disk with a fast fsync for Postgres (see [Sizing](#sizing)) and
  somewhere off the host to copy backups to.
- Optional, set later in the dashboard (Company settings): SMTP for outgoing mail, IMAP or
  Microsoft 365 mailboxes for tickets, QuickBooks Online or Xero. Optional now but worth
  deciding before the first customer: the [release signing key](#secrets-to-keep-safe), if you
  build your own images.

## Install

There are two stacks. Both run Postgres, the server and a backup job:

| | `deploy/docker-compose.yml` | `deploy/arcane/compose.yaml` |
|---|---|---|
| Image | built from source on the host (`--build`) | pulled from `ghcr.io/itzlcky/rivvie-rmm:${RMM_TAG}` |
| TLS | bundled Caddy, automatic certificate | none; put your own HTTPS reverse proxy in front of port 8080 |
| Use it when | you want one self-contained host | you already run a proxy, or deploy through Arcane, Portainer or similar, and want to pin a release tag |

The first one, from a checkout of a release tag (not `main`; see [Upgrades](#upgrades)):

```sh
git clone https://github.com/ItzLcky/rivvie-rmm.git && cd rivvie-rmm
git checkout v0.2.0
cp deploy/.env.example deploy/.env
```

Edit `deploy/.env`:

| Setting | Value |
|---|---|
| `RMM_DOMAIN` | the DNS name, no scheme |
| `POSTGRES_PASSWORD` | a long random string (`openssl rand -hex 24`) |
| `RMM_DATA_KEY` | `openssl rand -hex 32`. **Store a copy outside this host before going further**, see [Secrets](#secrets-to-keep-safe) |
| `BACKUP_KEEP_DAYS`, `BACKUP_INTERVAL_HOURS` | how many days of dumps to keep (14) and how often (24) |

Then:

```sh
docker compose -f deploy/docker-compose.yml up -d --build   # the first build takes a while
curl -fs https://rmm.example.com/healthz                    # prints ok
docker compose -f deploy/docker-compose.yml exec server \
  sh -c 'RMM_PASSWORD=... rmm-server create-user --email you@example.com --name You'
```

Sign in at `https://rmm.example.com`. Admins must set up two-factor auth (any authenticator
app) at the first sign-in; save the recovery codes. The Arcane stack can create the first admin
for you instead: set `RMM_ADMIN_EMAIL` and `RMM_ADMIN_PASSWORD` for the first start (they are
ignored once any user exists; remove them afterwards).

If the only admin loses their phone and recovery codes:
`docker compose -f deploy/docker-compose.yml exec server rmm-server reset2fa --email you@example.com`.

Check before enrolling anything: `docker compose -f deploy/docker-compose.yml logs server`
shows `listening on` and no `RMM_DATA_KEY isn't set` warning, and `docker compose ... ps` shows
`backup` running. Then take a first backup by hand (see [Backups](#backups-and-restore)) and
practise restoring it on a spare machine once, before you need to.

## TLS and the reverse proxy

**Bundled Caddy.** `deploy/Caddyfile` is two lines: `{$RMM_DOMAIN}` with `reverse_proxy
server:8080` (plus compression). Caddy obtains and renews a Let's Encrypt certificate itself, which
needs ports 80 and 443 open to the internet and `RMM_DOMAIN` resolving to the host. Its
certificates live in the `caddy` volume; keep that volume across upgrades so it doesn't
re-request them (Let's Encrypt rate-limits that). The compose file already sets
`RMM_TRUSTED_PROXIES=private`, so the server believes Caddy's `X-Forwarded-For`.

**Behind your own proxy** (nginx, Traefik, HAProxy, a cloud load balancer, or Caddy elsewhere):

- Forward everything to port 8080 of the server, including **WebSocket upgrades** for
  `/api/agent/ws` (every agent holds one open) and `/api/agents/*/shell` (terminals and remote
  desktop). Disable response buffering for those and raise the idle read timeout to at least
  a few minutes (agents ping, but a short default drops quiet sessions).
- Allow large request bodies on `/api/` up to `RMM_ATTACHMENT_MAX_MB` (100 by default); uploads
  stream, so don't buffer them to disk in the proxy either.
- Set `RMM_PUBLIC_URL` to the external `https://` URL (cookies get `Secure` from it, and
  install commands and portal links are built from it) and `RMM_TRUSTED_PROXIES` to the
  proxy's address, CIDR or `private`. If you skip the latter, every request looks like it came
  from the proxy and the sign-in rate limit applies to all users at once. Never trust a range
  that internet clients can reach.
- Terminate TLS with a publicly trusted certificate: agents verify against the OS trust store.
  A private CA works only if every agent host trusts it.
- Don't expose Postgres. Neither compose file publishes its port; keep it that way.
- Block or restrict `/metrics` at the proxy if you scrape from inside ([Monitoring](#monitoring)).

## Secrets to keep safe

| Secret | What it protects | If it leaks | If it's lost |
|---|---|---|---|
| `RMM_DATA_KEY` | Two-factor secrets, single sign-on client secrets, webhook signing secrets, IMAP and SMTP passwords, SIEM destination tokens, SNMP community strings and passphrases, the SMS provider's auth token and the Web Push (VAPID) signing key, the password vault's per-client keys, mailbox and accounting (QuickBooks, Xero) credentials, and detection context, all encrypted at rest | The encryption in the database and in backups is worthless to anyone who also gets the dump. Replacing the key needs the rotation procedure ([below](#rotating-rmm_data_key)) | The vault is gone for good; users with 2FA can't sign in until `rmm-server reset2fa` clears it; the server refuses to start once anything has been encrypted. **Keep it with your backups, in a password manager and a sealed copy off-site.** A backup without its key is half a backup |
| `POSTGRES_PASSWORD` | The database | Full read/write of everything. The database isn't published, so this takes access to the host or its Docker network first | Reset it in Postgres (`ALTER USER`) and in `deploy/.env` |
| Release signing key (`release.key`, from `rmm-sign keygen`) | Every agent self-update and all detection content: agents only run code signed by it | Anyone holding it can push their own binary to every agent. Treat it like a CA key: offline, never on the RMM server or the image, in CI only as the `RMM_UPDATE_SIGNING_KEY` secret | Agents can't be updated again; the public half is compiled into them, so they have to be reinstalled with a new key. Keep two copies off-site |
| `RMM_METRICS_TOKEN` | `/metrics` | Series names and fleet sizes; low impact. Rotate by changing it and the scraper | Set a new one |
| `RMM_ADMIN_PASSWORD` | Only used to create the first admin | Remove it from the environment once someone has signed in | |
| Enrollment tokens and packages | Anyone holding one can enroll machines into that site | Revoke the token in the dashboard. Tokens have an expiry and a use limit (30 days, 50 uses by default) | |
| Backups | Password hashes, agent credential hashes, sealed secrets | Written mode 0600 (`umask 077`); encrypt them where you copy them off-site | |

The public half of the release key (`RMM_UPDATE_PUBKEY`) isn't secret: it's built into agents and,
set on the server too, makes it verify uploaded detection content. Releasing and signing is
covered in [RELEASING.md](RELEASING.md) and the README's [Agent updates](../README.md#agent-updates).

### Rotating `RMM_DATA_KEY`

`rmm-server rotate-data-key` re-encrypts everything sealed with the key under a new one, in one
transaction: two-factor secrets, single sign-on client secrets, webhook signing secrets, IMAP and
SMTP passwords, SIEM tokens, mailbox and accounting credentials, detection context, the secret script parameters of jobs not yet delivered, and the vault's per-client keys (the vault's items
aren't touched). Stop the server first, then:

```sh
docker compose -f deploy/docker-compose.yml stop server backup
NEW=$(openssl rand -hex 32)      # store it in your password manager before going on
docker compose -f deploy/docker-compose.yml run --rm -e RMM_DATA_KEY_NEW=$NEW server rotate-data-key --dry-run
docker compose -f deploy/docker-compose.yml run --rm -e RMM_DATA_KEY_NEW=$NEW server rotate-data-key
# set RMM_DATA_KEY=$NEW in deploy/.env, then
docker compose -f deploy/docker-compose.yml up -d
```

The dry run changes nothing and fails if the current key doesn't open every value, so a wrong key
shows up before the real run. A failed run changes nothing and can be repeated; a finished one
can be run again and does nothing. Take a backup first and **keep it with the old key**: a backup
made before the rotation can only be restored with the key it was taken under. If the old key
leaked, also treat what it protected as exposed (sign-in secrets can be reissued, but a copy of an
old dump plus the old key still reads the vault as of that dump). The full procedure and what is
and isn't covered are in the README's [Backups](../README.md#deploying) section.

## Sizing

From the [November 2026 load test](research/load-test-2026-11.md): one `rmm-server` process and a
default Postgres container, on a 12-core desktop-class machine with a SATA SSD, held **10,000
agents** for 10 minutes with none dropped; the server process used about a quarter of a core
and about 1 GB of memory. **What gives out first is Postgres**, so size it, not the server:

| Fleet | Plan for |
|---|---|
| Up to ~1,000 agents | 2 cores, 4 GB RAM for the host; ~5 GB of database at the default retention |
| ~1,000 to ~10,000 | 4+ cores, 16 GB RAM; ~45 GB of database; NVMe |
| Beyond ~10,000 | The test found the limit between 10,000 and 20,000 on that machine (a mass reconnect after a restart overran the database, with errors for about three minutes). It also found that agent search (~0.8 s at 10,000 agents) and the dashboard's health calculation (~0.3 s, refetched on every alert, job and online change) are the first things to give. Plan for more than one node's worth only after measuring your own hardware |

(The first two rows are scaled from the 10,000-agent measurements and the storage figure, not measured themselves; the host sizes in particular are a starting point.)

- **Disk:** about **4.5 MB of database per agent** at the default retention, almost all of it raw
  heartbeat samples (`RMM_METRICS_RAW_DAYS`, 7). Halving that roughly halves the total; charts
  beyond 48 hours read the hourly rollups. Job output, tickets, the audit log, WAL and backups come
  on top. Ticket attachments and raw mail are separate files (the `files` volume) unless you use S3.
- **Postgres wants a disk with a fast fsync**: NVMe with power-loss protection, not a
  copy-on-write filesystem like btrfs (the test's 155 fdatasync/s made every connection wait on
  commits at 10,000 agents). Heartbeats commit asynchronously; job results, alerts and everything
  else don't.
- The connection pool is 32 connections and not configurable yet.
- After a server restart, agents reconnect and resend inventory; give a big fleet a few minutes
  before judging it.
- `rmm-loadgen` repeats the test against your own hardware (see the load test's *Reproducing*).

## Environment variable reference

Server (`rmm-server serve`; every setting is also a command-line flag, see `rmm-server serve
--help`). In the compose files, put them under the `server` service's `environment:`. A value
that fails to parse falls back to its default.

**Required and identity**

| Variable | Default | |
|---|---|---|
| `DATABASE_URL` | required | Postgres connection string; compose builds it from `POSTGRES_PASSWORD` |
| `RMM_PUBLIC_URL` | `http://localhost:8080` | External URL: install commands, portal and survey links, `Secure` cookies, accounting OAuth callbacks |
| `RMM_DATA_KEY` | empty (required by the compose files) | **Secret.** 32 bytes, hex or base64. See [Secrets](#secrets-to-keep-safe) |
| `RMM_BIND` | `0.0.0.0:8080` | Listen address (plain HTTP; put TLS in front) |
| `RMM_TRUSTED_PROXIES` | empty | Addresses/CIDRs, or `private`, whose `X-Forwarded-For` is believed |
| `RMM_ADMIN_EMAIL`, `RMM_ADMIN_PASSWORD` | empty | **Secret.** Create the first admin when no user exists; ignored afterwards |
| `RMM_PASSWORD` | | Password for `rmm-server create-user` (keeps it out of shell history) |

**Files and storage**

| Variable | Default | |
|---|---|---|
| `RMM_WEB_DIR` | `web/build` (`/srv/web` in the image) | Built dashboard |
| `RMM_AGENT_DIR` | `agents` (`/srv/agents` in the image) | Agent binaries offered for download, and their `.update.json` signatures |
| `RMM_STORAGE_DIR` | `data/storage` (`/srv/data/storage`) | Attachments and raw inbound email, unless S3 is set |
| `RMM_S3_BUCKET` | empty | Store those files in an S3-compatible bucket instead |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | | **Secret.** Credentials for the bucket (required when `RMM_S3_BUCKET` is set) |
| `RMM_S3_REGION` (or `AWS_REGION`) | `us-east-1` | |
| `RMM_S3_ENDPOINT`, `RMM_S3_PATH_STYLE` | empty, `false` for AWS | MinIO and other non-AWS stores (path-style is then the default; `true`/`false` overrides) |
| `RMM_ATTACHMENT_MAX_MB` | `100` | Largest ticket or portal attachment, per file |

**Agents, jobs and alerting**

| Variable | Default | |
|---|---|---|
| `RMM_HEARTBEAT_SECS` | `30` | Agent metrics interval |
| `RMM_INVENTORY_SECS` | `21600` | Agent inventory interval (6 h) |
| `RMM_PATCH_SCAN_HOURS` | `12` | Online agents scan for OS updates, and for the software catalog's installed versions, when their last scan is older |
| `RMM_JOB_QUEUE_DAYS` | `7` | Jobs queued for an offline agent expire after this |
| `RMM_AUTOMATION_RESTART_GRACE_MINUTES` | `10` | After the server starts, an agent's offline time (for the *comes back online* automation trigger) is counted from the start for this long, so a restart doesn't fire every automation |
| `RMM_ALERT_EVAL_SECS` | `60` | How often polled alert policies (offline, CPU, memory, disk) are evaluated |
| `RMM_CONTENT_SOAK_MINUTES` | `1440` | How long new detection content stays on canary clients before everyone gets it |
| `RMM_UPDATE_PUBKEY` | empty | The release public key (hex); when set, uploaded detection content is verified against it too. Build-time for agents (see [RELEASING.md](RELEASING.md)) |

**Retention and housekeeping**

| Variable | Default | |
|---|---|---|
| `RMM_METRICS_RAW_DAYS` | `7` | Raw heartbeat samples (charts up to 48 h, threshold alerts) |
| `RMM_METRICS_RETENTION_DAYS` | `90` | Hourly rollups (charts beyond 48 h) |
| `RMM_ALERT_RETENTION_DAYS` | `180` | Resolved alerts are deleted after this |
| `RMM_EMAIL_RAW_DAYS` | `90` | Raw MIME of inbound mail is deleted after this |
| `RMM_TICKET_CLOSE_DAYS` | `7` | Resolved tickets move to Closed after this |
| `RMM_SESSION_IDLE_HOURS` | `12` | Idle dashboard sessions are signed out (overridable in Company settings; 7 days at most) |
| `RMM_MAIL_POLL_SECS` | `60` | How often IMAP support mailboxes are checked |
| `RMM_SOURCE_URL` | the upstream repository | Where the console and portal's "Licence and source" link points (AGPL-3.0 §13). Set it to your own copy if you run modified code |

**Observability**

| Variable | Default | |
|---|---|---|
| `RMM_METRICS_TOKEN` | empty | **Secret.** Turns on `GET /metrics` for `Authorization: Bearer <token>`; without it the route answers 404 |
| `RMM_LOG_FORMAT` | `text` | `json`: one JSON object per log line |
| `RUST_LOG` | `info` | Log filter, e.g. `info,rmm_server::http=warn` for failed requests only |

**Integration endpoints** (only to point at a sandbox, a national cloud or a test double)

| Variable | Default | |
|---|---|---|
| `RMM_QBO_API_URL`, `RMM_QBO_AUTH_URL`, `RMM_QBO_TOKEN_URL` | Intuit production | `RMM_QBO_API_URL=https://sandbox-quickbooks.api.intuit.com` for the QuickBooks sandbox |
| `RMM_XERO_API_URL`, `RMM_XERO_AUTH_URL`, `RMM_XERO_TOKEN_URL` | Xero production | |
| `RMM_GRAPH_URL`, `RMM_GRAPH_LOGIN_URL`, `RMM_GRAPH_SCOPE` | Microsoft public cloud | Microsoft 365 mailboxes through Graph |
| `RMM_PAGERDUTY_URL` | `https://events.pagerduty.com` | PagerDuty Events API v2 (PagerDuty channels) |
| `RMM_OPSGENIE_URL` | the channel's region (`api.opsgenie.com`, `api.eu.opsgenie.com`) | Opsgenie channels; replaces both regions |
| `RMM_PUSH_ALLOW_HOSTS` | empty | Extra host names, comma-separated, Web Push subscriptions may point at (http allowed). Tests only: by default only Google, Mozilla, Microsoft and Apple push services are accepted |

QuickBooks and Xero redirect to `<RMM_PUBLIC_URL>/api/billing/accounting/qbo/callback` (and
`/xero/callback`): register that in the provider's developer portal.

`RMM_SLA_SWEEP_SECS` (default 30), `RMM_ONCALL_MINUTE_SECS` (default 60: how many seconds
one minute of escalation delay lasts) and `RMM_LOCALADMIN_TICK_SECS` (default 60: how often due
local admin rotations are sent) exist for tests; leave them alone.

**Compose-only** (`deploy/.env`): `RMM_DOMAIN`, `POSTGRES_PASSWORD`, `BACKUP_KEEP_DAYS`,
`BACKUP_INTERVAL_HOURS`. The Arcane stack also takes `RMM_TAG` (image tag), `RMM_PORT` (published
port, 8080).

**Agent** (set on the machine running `rmm-agent`; most installs need none of them):

| Variable | |
|---|---|
| `RMM_AGENT_CONFIG` | Path to `agent.toml` (default `/etc/rmm-agent/agent.toml`, or `C:\ProgramData\RMM\agent.toml`) |
| `RMM_ENROLL_TOKEN` | Enrollment token for `rmm-agent enroll`, as an alternative to `--token` |
| `RMM_STATE_DIR` | Where the agent keeps content, quarantine, telemetry and unsent results (tests run it unprivileged) |
| `RMM_SENSOR_SCAN_ROOTS`, `RMM_SENSOR_WATCH`, `RMM_SENSOR_CANARY_DIRS` | Sensor scan roots, watched directories and canary directories |
| `RMM_UPDATE_PUBKEY` (build time) | The release public key compiled into the agent |
| `RMM_AGENT_VERSION` (build time) | Version the agent reports, instead of the crate's |
| `RMM_SERVER`, `RMM_TOKEN` | MSI properties, not environment: `msiexec /i rmm-agent.msi RMM_TOKEN=<TOKEN> /qn` |

`rmm-sign` reads `RMM_UPDATE_SIGNING_KEY` (the hex key, for CI), `RMM_UPDATE_SIGNING_KEY_FILE`
and `RMM_UPDATE_PUBKEY`. The agent also has `RMM_*_FAKE` and `RMM_CONTENT_PUBKEY` switches that
exist only for tests and debug builds; never set them in production.

## Backups and restore

**What to back up**: the database, the `files` volume (`rmm-files` in the Arcane stack) unless you
use S3, and **`RMM_DATA_KEY`** (and your release key) kept with them. The `backup` job writes the
first two ([Object storage backups](#object-storage-backups)); the dump alone doesn't contain
ticket attachments, invoice PDFs or triage packages.

**Database and files.** The `backup` service writes `pg_dump -Fc` dumps (and the files tarball) every `BACKUP_INTERVAL_HOURS` into
`deploy/backups/` (the `rmm-backups` volume in the Arcane stack) and deletes ones older than
`BACKUP_KEEP_DAYS`. A backup on the same disk isn't a backup: copy the directory off the host
(rsync, restic or borg to another machine or a bucket, encrypted, with its own retention) and
check that the copy happens. Take one by hand before any change:

```sh
docker compose -f deploy/docker-compose.yml exec -T db pg_dump -U rmm -Fc rmm > rmm-before-change.dump
```

**Files by hand.** The job already archives them; to take one yourself:
`docker run --rm -v rmm_files:/data -v "$PWD":/out alpine tar czf /out/rmm-files.tgz -C /data .`
(the volume's real name is `<project>_files`; see `docker volume ls`). With
`RMM_S3_BUCKET`, enable bucket versioning instead and don't delete versions early.

**Restore** into an empty stack with the same `RMM_DATA_KEY`:

```sh
docker compose -f deploy/docker-compose.yml stop server
docker compose -f deploy/docker-compose.yml exec -T db dropdb -U rmm rmm
docker compose -f deploy/docker-compose.yml exec -T db createdb -U rmm rmm
docker compose -f deploy/docker-compose.yml exec -T db pg_restore -U rmm -d rmm < rmm-20260101T030000Z.dump
# and the files volume, if it was lost:
docker run --rm -v rmm_files:/data -v "$PWD":/in alpine tar xzf /in/rmm-files.tgz -C /data
docker compose -f deploy/docker-compose.yml start server
```

Then check `/healthz`, sign in, open a ticket with an attachment and an agent page. Agents
reconnect on their own within a minute or two (they hold their credentials, which are in the
database). A dump restored with the wrong `RMM_DATA_KEY` starts, but 2FA secrets and the vault
can't be read, and the server may refuse to start. **Practise this once** before you rely on it, on
a spare host.

The compose file's `backup` job and the README's [Backups](../README.md#deploying) section are
the source for these commands.

### Object storage backups

The `backup` job writes two files per run: `rmm-<ts>.dump` (the database) and
`rmm-<ts>.files.tar.gz` (the local object storage: ticket attachments, raw inbound email,
invoice PDFs, triage packages, uploaded software installers), taken dump first so a file is never missing for a row. Both are
written mode 0600 and pruned after `BACKUP_KEEP_DAYS`; copy them off the host.

With `RMM_S3_BUCKET` the tarball is empty: the files live in your bucket, so **turn on bucket
versioning** (and replication for real safety) and leave the bucket alone when restoring the dump.

To restore, stop the server, then run the `restore` service with a backup name (or `latest`);
it replaces the database in one transaction and refuses a non-empty storage directory unless
`RESTORE_REPLACE_STORAGE=1`:

```sh
docker compose -f deploy/docker-compose.yml stop server
docker compose -f deploy/docker-compose.yml --profile restore run --rm restore rmm-20260101T030000Z
docker compose -f deploy/docker-compose.yml start server
```

Start the server with the `RMM_DATA_KEY` the backup was taken under. CI runs the whole path as a
restore drill (`scripts/restore-drill.sh`: back up the e2e database and files with these scripts,
restore into an empty database and directory, read everything back including an attachment's
bytes), so the commands above are exercised, but still **practise a restore on a spare host once**.
See the README's [Backups](../README.md#deploying) section for details.

## Monitoring

Set `RMM_METRICS_TOKEN` (`openssl rand -hex 32`) and scrape `GET /metrics` with
`Authorization: Bearer <token>`. The README's [Monitoring the
server](../README.md#monitoring-the-server) has the series list, a Prometheus scrape config and
five alert rules worth having; at a minimum alert on:

- `up == 0` (server down), and `/healthz` from an external checker (it answers `ok`; it doesn't
  check Postgres, so pair it with the next);
- `rmm_agents_connected` dropping by a fifth in ten minutes (network, proxy or server);
- `rmm_outbox_oldest_seconds > 900` (notification or email delivery stuck);
- `rmm_db_pool_acquire_timeouts_total` increasing (Postgres can't keep up);
- disk space on the database and `files` volumes, and the age of the newest file in
  `deploy/backups/` (nothing in the stack alerts on a backup that stopped).

Logs: `RMM_LOG_FORMAT=json` for log shippers; every request is logged once with its route
template, status, duration and request id (also the `X-Request-Id` response header). Query
strings, bodies and headers are never logged. Keep the Docker log driver bounded
(`max-size`/`max-file`) or ship them elsewhere.

## Upgrades

Migrations run when the server starts and only go forward; there is no down migration. An upgrade
is a backup, a new image, and a check; a rollback is restoring that backup. The README's
[Upgrading](../README.md#deploying) has the full steps, which are the source of truth; in short:

1. Read the [CHANGELOG](../CHANGELOG.md) for the version: new variables, changed defaults.
2. **Back up**, right then (dump, `files` volume), and keep it with the `RMM_DATA_KEY` in use.
3. Move to the new release. Build-from-source stack: `git fetch --tags && git checkout v0.2.0`
   then `docker compose -f deploy/docker-compose.yml up -d --build`. Arcane stack: set `RMM_TAG=0.2.0`.
   Pin a tag in production, not `latest`, which follows `main`.
4. Verify: `/healthz`, `listening on` in the logs without migration errors, agents back online
   within a couple of minutes (`rmm_agents_connected` recovers), a ticket and an agent page open.
5. Roll agents forward once the server is happy: Agents → **Update N outdated**, or **Update
   agents automatically** in the agent policy. Agents roll themselves back if a new build can't
   reconnect within 120 seconds.

Rolling back means restoring the pre-upgrade dump into an empty database and starting the *old*
image with the same key; anything written in between is lost, so decide quickly. An old image
pointed at an upgraded database refuses to start.

CI's `upgrade` job migrates the previous release's data to the new code on every push, so a
release that is tagged from green `main` has been through this path. Releases are cut as in
[RELEASING.md](RELEASING.md).

## First clients and agents

In the dashboard: Clients & Sites → add a client, then **Enroll agents** on a site for the install
command, the agent downloads, or **Create package** for an `.msi`, `.deb` or `.rpm` with the
server URL and a dedicated token baked in (for Group Policy, Intune or other deployment tools).
The README's [Installing an agent](../README.md#deploying) covers the options. Set up the
[policies](../README.md#policies) your fleet should have, and an alert notification channel
(Company settings → Notifications), before enrolling many machines.

## On-call, text messages and push

Paging ([design/oncall.md](design/oncall.md)) and the installable app
([design/pwa.md](design/pwa.md)) need nothing on the server beyond outbound HTTPS:

- **Text messages** go through Twilio's Messages API, or any service that speaks it (set the API
  URL under Company settings → Notifications → SMS provider). Getting messages delivered is your
  side of it: buy a number, and in the US register the sender for A2P 10DLC (or use a toll-free
  verified number) before relying on it, or carriers drop the texts. Technicians verify their own
  mobile number with a code under Account → How to reach me.
- **PagerDuty and Opsgenie** channels reach `events.pagerduty.com` and `api(.eu).opsgenie.com`.
  Acknowledging in those services doesn't come back here (no inbound webhooks yet).
- **Web Push** reaches Google (`fcm.googleapis.com`), Mozilla, Microsoft and Apple push services.
  The server makes its VAPID key on first use and keeps it sealed with `RMM_DATA_KEY`; rotating
  the data key keeps it, and every browser's subscription stays valid. Push needs the dashboard
  on HTTPS. On iPhone and iPad it works only once the app is added to the Home Screen (iOS 16.4
  or later).


Nothing to install or open on the server: the site's **designated agent** (Network → Settings)
does the scanning and the SNMP reads, and sends the results over its normal connection. What it
needs from the network:

- **Reach.** The agent must be on (or routed to) the networks it scans and the devices it reads.
  Scans stay inside private address space (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`,
  `169.254/16`), at most 4,096 addresses at once, and the server and the agent both refuse
  anything else. Devices are read on UDP 161 (or the port you set).
- **Privileges.** None. ICMP is used when Linux lets the agent open a ping socket (running as
  root, or a group in `net.ipv4.ping_group_range`); otherwise discovery relies on TCP probes and
  the neighbour table. On Windows and macOS the same applies.
- **Credentials.** Make a read-only community or SNMPv3 user on the devices, add it under Network →
  Settings, and tick it for the site's scans. Secrets are sealed with `RMM_DATA_KEY` (listed in
  [Secrets to keep safe](#secrets-to-keep-safe), and resealed by `rotate-data-key`), travel to the
  designated agent only when it scans or reads, are never kept on it, and are never shown again.
- **Alerts.** Network alerts are items in the *designated agent's* policy set (Policies →
  Alerts: Network device down, Network interface down, Network device threshold). They are
  ordinary alerts, but do not count against that agent's health.
- **Storage.** Samples of monitored interfaces are kept for `RMM_METRICS_RAW_DAYS`, hourly
  rollups for `RMM_METRICS_RETENTION_DAYS`, like the agents' own. A device with 48 monitored ports
  read every five minutes is about 14,000 interface rows a day; ports become monitored the first
  time they're seen up, so unused ones cost nothing.
- **Agents older than this release** don't list the `network` capability and can't be designated;
  update them first.

Design and limits: [design/network.md](design/network.md).
