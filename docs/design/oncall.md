# On-call and paging

Design record, 2026-11-24. Plan: [parity-plan.md § D3](parity-plan.md#d3-on-call-and-paging-feature-10).
Migration `0046_oncall.sql`. Code: `crates/rmm-server/src/oncall.rs` (engine),
`src/api/oncall.rs` (API), `src/notify.rs` (channel kinds), `web/src/routes/settings/oncall`.

## Model

**Paging is a notification channel kind.** An alert item already chooses its channels, so
"critical server alerts page whoever is on call after hours" is an alert item whose
`channel_ids` include an `oncall` channel. There is no second routing engine.

- **Schedules** (`oncall_schedules`) have a time zone and **layers** (`oncall_layers`): a list of
  people, a start, a shift length (1 hour to 4 weeks) and optional **restrictions** (weekday and
  time-of-day windows, overnight allowed). A shift length that is a whole number of days hands
  over at the start's local time every time, across DST changes; other lengths are exact hours.
  Where layers overlap, the higher `position` that has someone on wins (in the UI, the lower
  one in the list).
- **Overrides** (`oncall_overrides`) put one person on for a stretch and win over every layer;
  of two overlapping overrides the one created later wins.
- **Escalation policies** (`escalation_policies`, `escalation_steps`): each step lists targets
  (`{schedule}` = whoever is on call then, `{user}`, or `{channel}` = another, non-on-call
  channel) and how many minutes to wait for an acknowledgement before the next step. After the
  last step the policy starts again `repeat` more times, then the page stays open without more
  notifications.
- **Pages** (`pages`): one escalation in progress for an alert or a ticket. `held` (waiting for
  business hours to end), `triggered`, `acknowledged`, `resolved`. At most one open page per
  alert (or ticket) and policy.
- **Deliveries** (`page_deliveries`): one message to one person by one method (or a step's
  channel), retried with `notify::backoff` up to 5 times.
- **Contact rules** (`user_contact_rules`): per person, methods (`push`, `sms`, `email`) each
  after a delay. Without rules: push and email at once, plus a text when the phone is verified.

`who_is_on_call(tz, layers, overrides, at)` and the escalation step function `next_step` are
pure and unit-tested (DST in London and New York, overnight restrictions, layer precedence,
overrides, repeats).

## Flow

1. The outbox (`notify::drain`) delivers an alert's `opened` event to an `oncall` channel:
   `oncall::trigger_alert` opens a page, unless the alert was already acknowledged or resolved.
   With `when: outside_hours`, a page opened while the channel's business calendar is open is
   `held` until the hours end (`Calendar::open_until`, added to `sla.rs`); if the alert is dealt
   with first, it is never sent.
2. `oncall::run` ticks every 15 seconds (and when woken): it follows alerts and tickets (an
   acknowledged or resolved alert acknowledges or resolves its pages and cancels pending
   deliveries), pages new P1 tickets when Company settings name a policy, notifies due steps and
   sends due deliveries.
3. Acknowledging a page (`POST /oncall/pages/{id}/ack`, or the alert's own Acknowledge, from the
   console or a push notification) stops it and acknowledges the alert. Resolving the alert
   resolves the page. Both directions are hooked (`api/alerts.rs`, `alerts::announce`) and the
   tick catches any path that isn't.

`RMM_ONCALL_MINUTE_SECS` makes a minute of delay shorter for tests.

## External channel kinds

Secrets live in the channel's existing sealed `secret` column; the API never shows them.

| Kind | Config | Sends |
|---|---|---|
| `sms` | `{to: [E.164…]}` | `POST {base}/2010-04-01/Accounts/{sid}/Messages.json` (Twilio, basic auth) with at most 300 characters |
| `pagerduty` | `{}` + routing key | Events API v2: `trigger` on open (and reminders), `resolve` on resolve; `dedup_key` = alert id |
| `opsgenie` | `{region}` + API key | Create with `alias` = alert id; close by alias on resolve |
| `oncall` | `{escalation_policy_id, when, calendar_id}` | Opens a page |

PagerDuty and Opsgenie are closed whenever their alert resolves, even if the item doesn't
notify on resolve (`notify::close_incidents`), or the incident would stay open there.

The SMS provider is Company settings (`sms_account_sid`, `sms_from`, `sms_base_url`,
`sms_token_enc` sealed with `RMM_DATA_KEY`, listed in `rotate::TABLES`).

## Text messages and the short link

A page's text is `[Brand] CRITICAL: <title> <public url>/a/<token>`, cut to 300 characters. The
token is random, stored hashed in `page_links`, single-use and valid 24 hours. `GET /a/<token>`
redirects to the alert (or ticket); acting on it still needs a signed-in session, so a leaked
text gives nothing away beyond its own words. Inbound replies ("ACK") are out of scope.

Mobile numbers are verified with a 6-digit code (stored hashed, 10 minutes, one try per code,
one code a minute).

## API and permissions

`/oncall/schedules` (CRUD, `…/shifts?from&to` for the timeline), `/oncall/now`,
`/oncall/overrides`, `/oncall/escalation-policies` (CRUD), `/oncall/settings` (P1 policy),
`/oncall/pages`, `/oncall/pages/{id}/ack`, `/oncall/people`, `/account/contact-methods`,
`/account/phone/verify`, `/settings/sms` (+ `/test`).

`oncall.manage` (new; admins by default) manages schedules, policies and anyone's overrides. Any
technician may put *themselves* on call with an override (and remove their own); technicians see
Settings → On-call for that. Public API: `getOnCallNow` (group `alerts`). Audit: `oncall.*`,
`page.ack`, `settings.sms`, `account.contact_methods`, `account.phone_verified`.

## Decisions and deviations from the plan

- The plan's `escalation_steps.delay_minutes` is read as "wait this long after this step before
  the next" (PagerDuty's meaning); step one is notified at once.
- `pages` gained `channel_id`, `title`, `severity` and `last_step_at`; `page_deliveries` gained
  `channel_id`, `step`, `round`, `sent_at`, and `user_id` is nullable (channel targets);
  `users` gained `phone_code_hash` and `phone_code_expires_at` for verification; there is a
  `page_links` table for the short links. The plan listed none of these.
- P1 ticket paging is a check in the worker (new P1 tickets of the last 15 minutes without a page)
  rather than a hook in the ticket code paths.
- An `oncall` channel's test checks its policy has steps instead of paging anyone.
- Ticket events on an `oncall` channel (SLA policies and boards can choose channels) page through
  its policy too.

## Merge notes

`0046` re-declares `notification_channels_kind_check` with the full list (`email`, `webhook`,
`slack`, `teams`, `sms`, `pagerduty`, `opsgenie`, `oncall`); another migration that changes it must
keep these. `alerts.agent_id` is joined with a `LEFT JOIN` in the engine, so the agentless alerts of
`0041` page too, though their text has no host name.

## Not proven here

Real Twilio, PagerDuty and Opsgenie (mock HTTP sinks in the e2e `oncall` section); carrier
delivery and A2P 10DLC registration.
