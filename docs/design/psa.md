# PSA design

The design for the built-in PSA (Phase 7 of [the roadmap](../ROADMAP.md)). Milestones 1-7 are built (the password vault isn't); the sections below are the plan as designed, with the decisions made while building it first.

## Decisions made while building milestones 1-2

- **Permissions model:** not needed until time and billing (rates must be hidden from some technicians). Tickets use the existing roles: read-only users read, technicians work tickets, admins configure boards and mailboxes. Do the permission sets before milestone 5, not before milestone 1.
- **Object storage:** a hard MinIO dependency is heavy for small installs. Local directory is the default; S3 is opt-in. Session recordings (Phase 6) can use the same `Storage`.
- **Priorities:** a `priorities` table added nothing; priority is 1-4 on the ticket with impact × urgency (1-3 each) computed in code. SLA targets will key on the number.
- **Search:** a generated `tsvector` column can't read other tables (timeline, contact), so triggers maintain it.
- **Triage:** unknown senders' tickets have no client. The existing scope filter (`client_id = ANY(scope)`) already hides them from scoped users, so triage needs no extra access rules.
- **Alert dedupe:** keyed on the alert's (policy, agent, key), not the alert row, so a flapping check reopens one ticket instead of opening many. "Untouched" is `touched_at IS NULL`, set by any person's action.
- **Email identity:** contacts are matched on `From`, never `Reply-To` (anyone can set that). An address used by two clients' contacts goes to triage rather than guessing.
- **Open questions answered:** multi-currency: store a currency per client (company default), decide before the invoice tables. Retention: raw MIME is pruned after `RMM_EMAIL_RAW_DAYS`; per-client purge of closed tickets (GDPR) is still open. Co-managed IT: works today through `user_clients` (a technician limited to one client sees only its tickets).

## Decisions made while building milestones 3-7

- **Portal auth:** contacts get a one-time emailed link by default (30 minutes; invitations a week), and can set a password and a TOTP. Portal sessions live in `contact_sessions` and use a cookie named `rmm_portal` scoped to `Path=/api/portal`, so the browser never sends it to the technician API, and `rmm_session` never authenticates a portal request. Asking for a link answers the same whether or not the address has access. Turning portal access off (or changing the email) ends the contact's sessions.
- **Who sees which tickets in the portal:** a contact sees tickets where they're the contact; primary contacts, and contacts given "sees every ticket", see all of the client's.
- **SLA pausing:** Waiting on client, Resolved and Closed stop the clock (resolved time doesn't count against resolution when a ticket is reopened). The paused business time is accumulated, and each deadline is `start + target + paused` in business time, so pausing needs no other bookkeeping. 75% points are stored next to the deadlines, so the sweeper is plain comparisons.
- **The update target** runs from the last public technician reply (or the first response) to the next one.
- **Which policy:** an active contract's, then the client's, then the default.
- **Microsoft 365:** Graph with an app registration (client credentials) rather than IMAP XOAUTH2, because it also sends: M365 tenants that turn off basic-auth IMAP usually turn off SMTP AUTH too. Replies are sent as MIME through `sendMail` so threading headers survive.
- **Money:** `bigint` minor units with an ISO currency per client (the company's by default); quantities are thousandths. Amounts are rounded once, when a quantity meets a price.
- **Cycles** are calendar-aligned (month, quarter, year) rather than anchored on each contract's start date, so every client's invoice covers the same period; a contract starting or ending mid-cycle is prorated by day. A contract's first partial cycle is picked up by the next run if it started after the last one. `contract_cycles` records what was billed, so nothing is billed twice, and deleting a draft frees it.
- **Coverage** is worked out when a timesheet is approved (not when time is logged), so rates and contracts as of approval apply and the technician never sees them. Rejecting a week undoes it (and gives block hours back) unless the time is on an invoice.
- **Numbering:** a single locked counter row instead of a sequence (sequences have gaps on rollback). Credit notes share the counter.
- **PDFs:** a small writer of our own (standard Helvetica, no embedded fonts, Windows-1252 text) instead of a PDF crate; enough for invoices and QBRs.
- **Accounting:** one provider connected at a time. The OAuth callback can't rely on the session cookie (SameSite=Strict isn't sent on the provider's cross-site redirect), so a one-time state, hashed and with an expiry, authenticates it.

## Goal and scope

The goal is a built-in PSA, so an MSP can run its service desk, contracts and billing in the same product as the RMM. The selling point is the link between the two: alerts open tickets, tickets show the device's live state, and invoices count the enrolled agents. A ticket tracker sitting next to the RMM wouldn't offer that.

Out of scope: general ledger, accounts payable, payroll and tax filing. Finalised invoices sync to QuickBooks Online or Xero, which handle those. We won't do payment processing either; at most an optional Stripe payment link on each invoice.

## Prerequisites

- **Per-client access control** (done in Phase 2: `user_clients`, scoped queries). Every PSA query is scoped by client. The client-portal role was deferred to here: it's the contacts auth below, and portal users must never reach technician endpoints.
- **Notification channels and outbound email** (Phase 4, done). Ticket replies, SLA warnings and invoice delivery all go through them.
- **Alert policies** (Phase 4, done). Alerts are the main automatic source of tickets.
- **Permission sets** (the mechanism landed with Phase 8: `users.permissions`, role defaults). The PSA needs finer roles: dispatcher, billing, and a technician who can log time but can't see rates or invoices. Add `tickets.*`, `billing.read`, `contracts.manage`, ... to the same mechanism before milestone 5.
- **Object storage** (done in milestone 1: local directory by default, S3/MinIO opt-in) for ticket attachments and invoice PDFs. Session recordings in Phase 6 can use it too.

## Data model

New tables. All of them hang off `clients` (and optionally `sites`/`agents`), so tenancy and access control carry over.

| Area | Tables | Notes |
|---|---|---|
| Contacts | `contacts` | People at a client (name, email, phone, site, `is_primary`, `portal_enabled`). Separate from `users`: contacts are customers, users are MSP staff. |
| Portal auth | `contact_sessions`, `contact_credentials` | Separate from `user_sessions` so a portal cookie can never authenticate against the technician API. Magic-link sign-in by default; password plus TOTP optional. |
| Tickets | `tickets`, `ticket_events`, `ticket_attachments`, `ticket_agents` | Human ticket number from a sequence (`T-10423`). `ticket_events` is an append-only timeline: public reply, internal note, status change, assignment, time entry, script run, merge. Many-to-many link to agents. |
| Queues | `boards`, `board_statuses`, `ticket_types` | Boards such as Service Desk, Projects or Alerts. Each has an ordered set of statuses, each mapped to a category (`new`, `open`, `waiting_client`, `waiting_vendor`, `resolved`, `closed`), which drives SLA pausing and reporting. |
| Priority | `priorities` | Impact × urgency matrix that resolves to P1–P4. |
| SLA | `sla_policies`, `sla_targets`, `business_calendars`, `holidays` | Response, first-update and resolution targets per priority. Business hours per calendar, with timezone. A client's contract chooses its policy. |
| Time | `time_entries`, `work_types`, `work_roles` | Start/end or a duration. Each entry has a billable flag, a work type (remote, onsite, after-hours), the technician and the ticket or project. `invoice_line_id` is set once billed, which locks the entry. |
| Contracts | `contracts`, `contract_items`, `contract_rate_overrides` | Agreement types: managed per device, managed per user, block hours (prepaid bank), time and materials, and flat recurring. Each has a start/end date and a billing cycle, and covers some work types (in scope vs. billable on top). |
| Catalog | `products` | Recurring and one-off items (licences, hardware, labour SKUs), with cost and price. |
| Billing | `invoices`, `invoice_lines`, `invoice_number_seq` | Lifecycle: draft → finalised → sent → paid/void. A finalised invoice is immutable and numbered without gaps; corrections are credit notes. Money is `bigint` minor units plus an ISO currency code, never floats. |
| Knowledge | `kb_articles`, `client_docs` | KB articles, internal or public in the portal. Per-client documentation pages (network layout, vendors, procedures). |
| Scheduling | `schedule_entries` | A technician, a time range, and a link to a ticket or project. |
| Projects | `projects`, `project_phases`, `project_tasks` | Budgeted hours with burn-down; tasks can spawn tickets. Comes last (see the build order). |

Search uses Postgres full text: a generated `tsvector` over ticket subject, events and contact name, with a GIN index. That's enough until the data is very large.

## Ticket intake

- **Dashboard and portal:** forms, with ticket type and priority. The portal form can ask type-specific questions.
- **Email-to-ticket:** one or more support mailboxes per company. There are three ways to receive mail: IMAP IDLE/poll, Microsoft Graph subscriptions for M365 mailboxes (the common case for MSPs), or an inbound webhook from Postmark, SES or Mailgun.
  - Threading: match on the `[T-10423]` subject tag first, then `In-Reply-To`/`References` against the `Message-ID`s we sent. Otherwise open a new ticket.
  - Sender → contact → client: match the exact address first, then the client's email domains. Unknown senders go to a triage queue; don't auto-create contacts.
  - Loop protection: ignore `Auto-Submitted: auto-*`, `Precedence: bulk/junk/list` and bounces (DSNs). Rate-limit auto-replies per sender. Never auto-reply to our own mailboxes.
  - Strip quoted reply text when storing an event, but keep the raw MIME in object storage.
- **Alerts (the RMM link):** an alert policy can open a ticket on a chosen board and priority.
  - Deduplicate: while the same alert on the same agent has an open ticket, add an event to it instead of opening a new one.
  - When the alert clears, add a note. Optionally auto-resolve the ticket if nobody has touched it.
  - Flap protection: count the reopens and stop auto-resolving after N.
- **API and webhooks:** with the public API (roadmap: Platform). Lets monitoring tools and forms outside the RMM create tickets.

## Working a ticket

- The ticket page has a sidebar with the linked agents' live status, last metrics, recent alerts and patch status. From there a technician can:
  - run a library script, with the job output attached to the timeline as an internal note;
  - open a web terminal (or remote desktop, Phase 6), with session start/end recorded as an event and a time entry suggested from the duration.
- **Timer:** start/stop on the ticket. Logging time asks for the work type and billable flag and, optionally, writes the note as a public reply.
- **Assignment and dispatch:** assign to a technician or a team. The dispatcher's calendar view lets them drag tickets onto technicians' schedules. Two-way sync with M365 and Google calendars comes later.
- **Bulk actions:** merge duplicates, split a reply into a new ticket, and change status, assignee or priority in bulk.
- **Canned responses and macros:** set status, add a note, assign. Templates have variables (`{{contact.first_name}}`, `{{ticket.number}}`).
- **Satisfaction survey:** sent on close, one click, with optional feedback. Results feed reporting.

## SLA engine

- When a ticket is created, or its priority or contract changes, compute `respond_by`, `update_by` and `resolve_by`. Use the contract's SLA policy and its business calendar in the client's timezone, minus holidays.
- Store these deadlines on the ticket so list views can sort and filter without recomputing.
- Statuses in the `waiting_client` category pause the clock. Store the accumulated paused time so the deadlines shift without extra bookkeeping.
- A background task (alongside the existing job-lifecycle sweeper) sends warnings at 75% and on breach through the notification channels. It records `sla_breached_at` so attainment reporting is cheap.
- First response counts only on a public reply by a technician. Internal notes and automated messages don't count.

## Time, contracts and billing

- **Rate lookup**, first match wins: contract rate override for the work type → work-role rate → work-type default → technician default.
- **Contract coverage:** per-device and per-user agreements cover their in-scope work types at no extra charge, and anything else becomes billable. Block-hours contracts draw down the bank and bill any overage at the overage rate. A low-balance warning goes to the account manager.
- **Device counts come from the RMM:** per-device contracts bill on the number of agents enrolled under the client on the cycle date, optionally filtered by OS (workstation vs. server pricing). Snapshot the count onto the invoice line so later enrolments don't change a finalised invoice.
  - Per-user contracts use a manually entered count. M365 licence counts via Graph could feed it later.
- **Time approval:** technicians submit timesheets weekly and a manager approves them. Only approved, billable entries that no contract covers reach an invoice.
- **Invoice run** (monthly, or per contract cycle) generates drafts per client:
  - recurring contract lines, prorated for mid-cycle starts;
  - device and user counts;
  - uncovered billable time;
  - products sold on tickets.
  - A person reviews and edits the drafts, then finalises: numbering, PDF and email to the client's billing contact. Every billing change goes in `audit_log`.
- **Accounting sync:** push finalised invoices, customers and items to QuickBooks Online or Xero over OAuth. Pull payment status back. Tax comes from the accounting system's tax codes; we don't calculate it ourselves.

## Client portal

A separate route group (`/portal`) with its own layout and branding (company name and logo from Company settings). Contacts can:

- view and reply to their tickets, open new ones and upload attachments;
- see a read-only status list of their client's devices (online, last seen, patch compliance). Off by default, enabled per client;
- read public KB articles;
- if they're a billing contact: see invoices and their PDFs, and the payment link if one is configured.

Portal access is scoped to one client in the session and checked on every query. This depends on the per-client access work in Phase 2.

## Documentation and credentials

Per-client documentation pages are straightforward. A **password vault** is a separate, larger decision: it would hold the most sensitive data in the product. If we build one:

- envelope encryption: a per-client data key wrapped by a key that isn't in Postgres (KMS, or a key file mounted only on the server);
- reveal on request with a mandatory audit entry;
- a permission of its own;
- 2FA required to view.

Do this before the vault: encrypt the TOTP secrets at rest. Phase 8 added `RMM_DATA_KEY` and ChaCha20-Poly1305 sealing (`crates/rmm-server/src/crypto.rs`), but TOTP secrets are still plaintext in Postgres.

## Reporting

- Service desk: tickets opened and closed per client, board and technician; backlog age; first-response and resolution times; SLA attainment; CSAT.
- Utilisation: billable hours vs. logged hours vs. available hours per technician.
- Client profitability: invoiced revenue against time cost (hours × a loaded cost rate per technician) plus product cost.
- Quarterly business review (QBR) PDF per client, combining PSA and RMM data: ticket trends, top issues, SLA attainment, device count, patch compliance, alerts and uptime.

## Web UI

Built on the Phase 3 components, under the sidebar's Service desk group. New top-level sections: **Tickets** (board/list views, saved filters), **Schedule**, **Contacts** (or a tab under Clients), **Contracts**, **Billing** and **Knowledge**. Client and agent pages get Tickets tabs. Settings gets boards and statuses, SLA policies and calendars, work types and rates, the product catalog, mailboxes, and accounting integration.

## Suggested build order

1. **Ticketing core:** contacts, tickets, timeline, boards/statuses/priorities, assignment, attachments, search, and agent links with the live-status sidebar.
2. **Email and alerts:** outbound replies and notifications; inbound email-to-ticket with threading and loop protection; alert → ticket with dedupe and auto-resolve.
3. **Client portal:** separate auth, tickets, KB.
4. **SLA:** policies, business calendars, deadline computation, pause, warnings and breaches.
5. **Time and contracts:** timer, time entries, work types and rates, contract types and coverage rules, timesheet approval.
6. **Billing:** invoice runs, finalisation, PDFs, QuickBooks Online/Xero sync.
7. **Scheduling, projects, documentation, reporting, QBRs.** The vault, if we build one, comes last and gets its own security review.

Each milestone should be usable by itself. After step 2, an MSP can already run its service desk here and bill from another system.

## Open questions

- **Build vs. integrate.** Many MSPs already use HaloPSA, ConnectWise Manage or Autotask and won't switch. Keep a sync integration (roadmap: Later) for them alongside the built-in PSA: alerts → their tickets, and agents → their configurations.
- **Multi-currency:** one currency per company is simpler; one per client is what MSPs billing across borders need. Pick one before creating the invoice tables.
- **Retention:** how long to keep raw email MIME and attachments, and whether closed tickets can be purged per client (GDPR requests from a client's contacts).
- **Who works the tickets:** if a client's own IT staff (co-managed IT) need to work tickets, they need technician-like access limited to one client. This is the same `user_clients` work from Phase 2.
