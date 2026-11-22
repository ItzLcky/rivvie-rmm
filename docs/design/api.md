# API keys, the public API and webhooks

Other tools (reporting, automation, a customer's own PSA) talk to the RMM through API keys, a documented REST API and outbound webhooks. Everything here reuses the dashboard's own handlers, so scoping, permissions and audit behave exactly as they do for a person.

## API keys

A key is `rmm_k_` plus 64 hex characters, sent as `Authorization: Bearer rmm_k_…`. Only its SHA-256 is stored; the first 12 characters (`prefix`) are kept to tell keys apart in lists and logs. The secret is shown once, when the key is created.

A key **acts as its owner and never with more**. It is created by a signed-in user for themselves (Account → API keys), or by an admin for a *service account*: a user with `service_account = true`, role technician or read-only (never admin), that can't sign in (its password hash is the unusable `!`, sign-in and admin password resets refuse it) and whose client access and permission set are managed like any user's. What a key can do is the intersection of:

| Limit | Meaning |
|---|---|
| `access` | `read` (only `GET`) or `write`. Write needs an owner who is a technician or admin. A write key acts as at most a technician, whatever its owner's role: nothing admin-only is in the API. |
| `scopes` | Resource groups the key may call: `clients`, `agents`, `jobs`, `scripts`, `alerts`, `tickets`, `security`. At least one. |
| `permissions` | Named permissions (`security.read`, `billing.manage`, …). A key has **only** the ones it lists, and only those its owner holds, so a technician's key doesn't carry `vault.read` or `security.respond` unless it asks. Handlers check them as for users (`u.need(Perm::SecurityRead)`). |
| `client_ids` | Optional subset of clients; null means every client the owner can see. |
| expiry, rate limit | `expires_at` (optional; the dashboard defaults to 90 days) and `rate_limit_per_min` (default 600), a token bucket per key in memory. Over it: 429 with `Retry-After`. |

The key's rights are narrowed against the owner **on every request** (`apikeys::narrow`): demoting the owner, removing a client, withdrawing a permission or disabling the account takes effect immediately, and creation refuses what the owner doesn't hold (`400`). Revoking sets `revoked_at`; revoked, expired and unknown keys are `401`.

Mechanism: `auth::User`'s extractor sees a `rmm_k_` token and calls `apikeys::authenticate`, which returns a `User` already narrowed (role, permissions, client scope, `api_key = Some(id)`). Handlers don't change. Keys never reach `session_user`, so the live event stream, the agent socket and the shell and desktop relays (which authenticate sessions themselves) refuse them.

### What keys can reach

Only routes in the registry `api::public::OPS`, each with its group; anything else is `403 this endpoint isn't available to API keys`. A new dashboard route is therefore **not** public until someone adds it there. The registry is also what the OpenAPI document is generated from, so docs and enforcement can't drift (unit tests check that every entry is a real route, and that nothing like the shell, desktop, vault, auth, users, settings or key management is listed).

Deliberately not in the API: the agent protocol and enrollment, shell and desktop relays, processes and file transfer, service control, the password vault (reveal included), users, sessions, settings, billing and invoices, policy management, security *response* actions, and key and webhook management. Creating jobs is limited to **saved scripts** (`script_id`): a key can't push ad-hoc code to endpoints. Writes made with a key are audited as `api.request` (key id and prefix, method, path); reads are not (they would drown the log), but `last_used_at` and `last_used_ip` are kept per key. Key and service-account management is audited (`api_key.create`, `api_key.revoke`, `service_account.*`).

### Versioning

The same router is mounted at `/api` (the dashboard's, session cookies) and `/api/v1` (what integrations use). The OpenAPI document's `servers` names `/api/v1`. A breaking change would add `/api/v2` and leave v1 running; additions (new fields, routes, events) are not breaking, so clients must ignore what they don't know.

## OpenAPI

`GET /api/openapi.json` (and under `/api/v1`) returns an OpenAPI 3.1 document built from the registry, with schemas for the main resources. It needs no credentials: it describes the API, not data. The dashboard renders it at `/api-docs` (linked from Account and Company settings → API).

## Webhooks

Admins subscribe a URL (Company settings → Webhooks) to a set of events, optionally for one client. Events:

| Event | When |
|---|---|
| `ticket.created` | a ticket is opened (dashboard, API, email, portal, alert, project) |
| `ticket.updated` | a field, agent link, page link, merge or split changed the ticket |
| `ticket.status_changed` | the status changed (`change.category`: new, open, waiting_client, waiting_vendor, resolved, closed) |
| `ticket.resolved` | the new status is in the `resolved` category (sent after `status_changed`) |
| `ticket.comment` | a public reply, a client's message or an internal note (notes only to subscriptions with `internal_notes`) |
| `alert.created`, `alert.acknowledged`, `alert.resolved` | the alert's lifecycle; alerts held back by a mute are announced when the mute ends, like notifications |
| `ping` | the Test button; not subscribable |

Ticket events are written by `tickets::add_event` **in the transaction that changes the ticket**, so there is no event for a change that rolled back and none lost to a crash after commit. Alert events are queued right after the alert changes (like notifications).

Delivery is `POST <url>` with `{id, event, created_at, data}`; `data` has `ticket` or `alert`/`agent`/`client`/`site`, the `change` or `comment`, and the `actor`. Headers: `X-RMM-Event`, `X-RMM-Delivery` (= `id`) and `X-RMM-Signature: sha256=<hex HMAC-SHA256 of the raw body>` with the subscription's secret, the same scheme as the webhook notification channel. The secret (`whsec_…`) is generated by the server, shown once, stored sealed with `RMM_DATA_KEY` when it's set, and can be rotated. A retry resends identical bytes with the same delivery id, so receivers can deduplicate on it.

The table `webhook_deliveries` is the outbox and the delivery log: the notification worker claims due rows with a lease (`FOR UPDATE SKIP LOCKED`), sends them concurrently, and retries failures after 1, 5, 30 and 120 minutes (`notify::backoff`), giving up after 5 attempts. Any 2xx is success. The log (status, attempts, HTTP status, duration, error) is in the dashboard, with *Send again* per delivery; rows older than 30 days are pruned.

URLs must be `http(s)` without embedded credentials. Internal addresses are allowed on purpose (admins configure them; receivers are often on the same network), so only admins can create subscriptions.

## Left for later

Per-key IP allowlists, webhooks for more resources (devices, jobs, time), delivery to a queue instead of HTTP, API access for the client portal, OAuth/OIDC client credentials for service accounts, and PATCH-style management of keys.
