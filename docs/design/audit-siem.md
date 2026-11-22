# Audit log export, the SIEM stream, and sealed credentials

Migration `0031_audit_siem_sealing.sql`. Code: `api/audit.rs`, `siem.rs`, `api/siem.rs`,
`rotate.rs`; page: Audit log (Export) and Company settings → SIEM.

## Export

`GET /api/audit/export` (and `/api/v1/audit/export` with an API key) streams the audit log as CSV
(`format=csv`, the default) or JSON Lines (`format=jsonl`), oldest first, with the same filters as
the audit page: `action` (exact, or a prefix ending in `.`), `user_id`, `target_type`, `target_id`,
`from`, `to` (RFC 3339). The rows are read with a database cursor and written in 64 KiB chunks
through a bounded channel, so the table is never held in memory and a slow client slows the
query instead of filling RAM. A query that fails part way aborts the connection: a truncated file
never looks complete.

- Needs the new permission `audit.read`: admins always, anyone else only if an admin grants it
  (Company settings → Users). The list (`GET /audit`) needs the same.
- The export is itself audited (`audit.export`, with the format, the filters and whether it came
  from a session or an API key), before the first byte is sent.
- CSV fields that start with `=`, `+`, `-`, `@`, a tab or a CR are prefixed with `'` so a
  spreadsheet doesn't run user names and details as formulas.
- Public API: scope `audit` (listed in the key form) plus the key's own `audit.read` permission,
  operations `listAudit` and `exportAudit` in the OpenAPI document.

## SIEM stream

Admins add destinations under Company settings → SIEM (`/api/siem/destinations`; not part of the
public API). Each destination picks what it receives: the audit log, security detections, alerts.

| Type | Wire format |
|---|---|
| Syslog over UDP | One RFC 5424 message per datagram |
| Syslog over TCP | RFC 5424, RFC 6587 octet counting (`<len> <msg>`) or one message per line |
| Syslog over TLS | RFC 5424 with RFC 5425 octet counting; certificate checked against the system roots and an optional CA you paste |
| HTTPS | `POST` of `{"source", "host", "events": [...]}` with `Authorization: Bearer <token>`, or Splunk HEC (one `{time, host, source, sourcetype, event}` per line, `Authorization: Splunk <token>`) |

A syslog message is `<PRI>1 TIMESTAMP HOST rmm-server - MSGID [rmm@32473 kind="audit" id="42"
event="audit.user.login"] {json}`; PRI is facility (default 13, log audit) × 8 + severity
(audit: informational; alerts: critical → 2, warning → 4; detections: severe → 2, high → 3,
moderate → 4, low → 5). The structured-data id `rmm@32473` uses the enterprise number reserved
for documentation (RFC 5612); we have no IANA number. A message over 8000 bytes is sent without its
`details`, with `"truncated": true`. The JSON carries the audit row's `id`, `ts`, `action`,
`user_email`, `target_type`, `target_id` and `details`; detections and alerts carry the host,
client, severity and state, and a detection never carries its sealed `context`.

### Delivery

Triggers on `audit_log`, `security_detections` (created, status changed, resolved) and `alerts`
(opened, acknowledged, resolved) write one `siem_outbox` row per event per enabled destination
that wants it, in the transaction that wrote the event. The worker (`siem::run`) claims a due
destination with a lease, sends up to 200 events per batch (at most 10 batches per round) in id
order, and deletes them once sent. So:

- **Nothing is lost across a restart or an outage**: unsent events stay in the table.
- **At least once**: a crash between sending and deleting repeats a batch. Every event has its
  audit `id`, so a collector can drop repeats.
- **Backoff**: a failing destination waits 5 s, 10 s, 20 s … up to 15 minutes; events keep
  queueing. Saving the destination retries at once. The settings page shows status, events sent,
  waiting and dropped, the last delivery and the last error, and a **Test** button sends one event
  right now (not queued) and reports the result.
- **Retention**: events not sent within 7 days are deleted and counted as dropped, so a destination
  that is down for good can't fill the database.
- Only events from the moment a destination is created or enabled are sent; nothing is replayed.
- A destination's token is sealed with `RMM_DATA_KEY` and never returned; `rotate-data-key`
  rotates it.

Not done: per-client filtering of the stream (it's an admin-level, whole-installation feed),
mutual TLS to the collector, and UDP message fragmentation (one datagram per event, so keep the
collector's receive buffer above 8 KB).

## Sealed credentials

Found by grepping the migrations for password, secret and token columns. Stored in the clear
before this change, now sealed with `RMM_DATA_KEY` (`crypto::store`), never returned by the API,
and listed in `rotate::TABLES`:

| Where | Was | Now |
|---|---|---|
| `mailboxes.imap_password` | `text` | `imap_password_enc` + `imap_password_sealed` |
| `company_settings.smtp_password` | `text` | `smtp_password_enc` + `smtp_password_sealed` |
| webhook notification channel signing secret | `notification_channels.config -> 'secret'` (jsonb) | `notification_channels.secret` + `secret_sealed` |

The migration can't seal (it hasn't the key): it moves each value into the new column with the
flag false and blanks the old column before dropping it. At startup, with `RMM_DATA_KEY` set,
`rotate::seal_plaintext_credentials` seals every row still flagged false; without a key such rows
stay readable, like the TOTP secrets. A server with sealed values and no key refuses to start.
Old row versions of the dropped columns stay in dead tuples until vacuum, and in backups taken
before the upgrade: change the IMAP/SMTP passwords if that matters to you.

Reviewed and left as they are, on purpose:

- Slack and Teams channel URLs (`notification_channels.config.url`): the URL is the credential, but
  admins see and edit it in the dashboard by design. Moving it into the sealed column would mean
  hiding it from the form.
- `sso_login_states.code_verifier` and `nonce`: single use, deleted after at most 10 minutes.
- Everything else matching `password`, `secret` or `token` is a hash (`password_hash`,
  `token_hash`, `secret_hash`), already sealed (TOTP, SSO and webhook secrets, accounting tokens,
  vault keys), or a public identifier.
