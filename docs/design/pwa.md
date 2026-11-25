# Technician mobile access: the installable app and Web Push

Design record, 2026-11-24. Plan: [parity-plan.md § D4](parity-plan.md#d4-technician-mobile-access-pwa-feature-14).
Migration `0047_push.sql`. Code: `crates/rmm-server/src/push.rs`, `src/pwa.rs`, `src/api/push.rs`,
`web/src/service-worker/`, `web/src/lib/push.ts`, `web/src/lib/shell/BottomNav.svelte`.

## Installable

- `GET /manifest.webmanifest` is served by the server: name, short name, colours and icons, with
  `display: standalone` and `start_url: /alerts`. **The branding comes from one function,
  `pwa::manifest_branding`**, which today uses the company name and built-in colours and icons
  (`web/static/icons`, rendered from the favicon); when the branding feature lands it switches to
  `branding::resolve(None)` and icons resized from the branding icon.
- `app.html` links the manifest, sets `theme-color` and the Apple touch icon.
- The service worker (`src/service-worker/index.ts`, SvelteKit 3: `$app/manifest` and
  `$app/env`, not the old `$service-worker`) precaches the built files and `static/`, serves them
  from the cache, falls back to `offline.html` for navigations that fail, and never touches
  `/api`: API responses hold client data and are never cached. No offline writes.
- The CSP's `default-src 'self'` covers `worker-src` and `manifest-src`; the Playwright `mobile`
  project checks that Chrome parses the manifest without errors and that the worker activates.
- Installed (display mode `standalone`), phones get a tab bar at the bottom (Alerts, Tickets, Time,
  Devices, More), and the alert page keeps Acknowledge and Resolve in a sticky bar.

## Web Push

- **Encryption** (RFC 8291, `aes128gcm`) and **VAPID** (RFC 8292, ES256) are implemented with
  `ring`, already a dependency: P-256 ECDH with a fresh key per message, HKDF-SHA256,
  AES-128-GCM, ECDSA P-256. No new crate. Unit tests: the RFC 8291 Appendix A vector (from the
  shared secret on, as `ring` can't import a fixed ECDH private key), a round trip decrypted as a
  browser would, and the VAPID JWT verified with the public key.
- The VAPID key pair is made on first use (`push_keys`, private key PKCS#8 sealed with
  `RMM_DATA_KEY`, in `rotate::TABLES`).
- **Endpoints** must be https on `fcm.googleapis.com`, `*.push.services.mozilla.com`,
  `*.notify.windows.com` or `*.push.apple.com`, port 443; anything else is refused at subscribe
  and at send, so a user can't aim the server at an internal URL. `RMM_PUSH_ALLOW_HOSTS` adds
  hosts for tests. A 404 or 410 deletes the subscription.
- **Payload**: `title`, `body`, `url`, `alert_id`, `tag`, `kind`. With "hide details" on, the
  body says only "New critical alert" and the like.
- **What sends**: an alert opening (critical or warning) to everyone who can see the client, has
  a device and wants that severity (`push::alert_opened`, called from `alerts::announce`); the
  `push` contact method of a page; and the staff ticket mails in `email.rs` (`queue_staff`:
  assigned, client reply, SLA). Alerts and tickets go through `push_outbox` so the alert engine
  never waits on a push service. The service worker's **Acknowledge** action posts
  `/api/alerts/{id}/acknowledge` with the session cookie (the plan said `/ack`; the route is
  `/acknowledge`), which also acknowledges any page.
- **Preferences** (`user_notification_prefs`, per event, push and email): `page`,
  `alert_critical`, `alert_warning`, `ticket_assigned`, `ticket_reply`, `sla_warning`. Push
  defaults on for pages, critical alerts and assignments; email defaults on. The email switch
  applies to the ticket mails only (alerts email through channels, pages through contact rules).

API (session only, not in the public API): `GET /push/key`, `GET|POST|DELETE /push/subscriptions`,
`POST /push/test`, `GET|PUT /account/notification-prefs`.

## Phone layouts

The Playwright `mobile` project (390×844, touch) has baselines and axe checks for alerts, an
alert, tickets, a ticket, time and the account page with the tab bar, and checks the tab bar's
targets are at least 44 px tall.

## Not proven here

Delivery through the real Chrome, Firefox, Edge and Safari push services, and the installed app
on iOS (16.4+) and Android. The e2e `push` section uses a local endpoint and decrypts the body
itself.
