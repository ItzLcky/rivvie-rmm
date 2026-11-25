# End-user tray app

Design record, 2026-11-24. Built from Phase G of the [parity plan](parity-plan.md). Migration `0052_tray.sql`.

## Shape

`rmm-agent tray` is a subcommand of the agent binary, run **as the signed-in user**. It talks to the agent service over a local socket and never to the server. The service end (`crates/rmm-agent/src/tray/server.rs`) forwards help requests over the agent's WebSocket and routes consent prompts and notices back.

| | Windows | Linux |
|---|---|---|
| Started by | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\RmmAgentTray` = `"…\rmm-agent.exe" tray`, from the MSI's `Registry` table and from `rmm-agent install` (removed by uninstall) | `/usr/share/applications/rmm-tray.desktop` (launcher: `rmm-agent tray`) and `/etc/xdg/autostart/rmm-tray.desktop` (`rmm-agent tray --background`), from the deb and rpm |
| UI | Raw Win32 (`tray/win.rs`): `Shell_NotifyIconW` icon (the branding icon PNG via `CreateIconFromResourceEx`, else the stock icon), a popup menu, a hand-built form window, message boxes | No icon. The launcher opens the form with zenity (`--forms`) or kdialog and exits; `--background` stays connected and shows prompts (`zenity --question --timeout`) and notices (`notify-send`) |
| IPC | Named pipe `\\.\pipe\rmm-agent-tray` | Unix socket `/run/rmm-agent/tray.sock` (`$RMM_STATE_DIR/tray.sock` when that is set; `RMM_TRAY_SOCKET` overrides) |
| Peer | `GetNamedPipeClientProcessId` → `ProcessIdToSessionId` and the process token's user (`LookupAccountSidW`: `DOMAIN\user`) | `SO_PEERCRED`: uid → login name (`getpwuid_r`); the session is the uid |

Everywhere: `rmm-agent tray --request --subject … [--body …] [--screenshot file]` sends a request without any window and prints `ticket #N created` or `queued: …` (exit 1 with the reason when refused), and `--show-config` prints what the tray would show as JSON. macOS has only these two.

## IPC (`tray/ipc.rs`)

Frames are a u32 little-endian length and a MessagePack body. `TrayToAgent`: `Hello { version, link }`, `GetConfig`, `HelpRequest { subject, body, screenshot }`, `ConsentAnswer { id, allow }`. `AgentToTray`: `Config`, `HelpResult { request_id, ticket_number, queued, error }`, `Consent { id, title, text, timeout_secs }`, `Notice { text, active }`, `Restart`, `Error`.

The decoder is one small struct: it rejects a length over `MAX_FRAME` (5 MiB + 64 KiB) before reading the body, and a body that isn't one of the messages above is an error. Unit tests split frames byte by byte, feed oversized and malformed frames, and run 3,000 rounds of random bytes (some with plausible length prefixes and tag keys) through the decoder and both message decoders.

## The service end: the tray is untrusted

Any local user can connect. A connection must say `Hello` within 10 seconds; one-off connections close after 2 minutes idle; at most 64 connections and 4 long-lived links per session. The service accepts only:

- **Read** the config (contact card, product name, links, switches).
- **Submit a help request**: subject 1–300 characters (one line), description up to 5,000, screenshot up to 5 MiB and JPEG or PNG by content. Five per user per hour (in memory, by the peer's account name, not anything the tray says). Refused when the policy has the tray or "request help" off.
- **Answer a consent prompt** that was sent to *that connection*, once.

Nothing else: no paths, no commands, no server traffic of the tray's choosing. User and session always come from the OS's view of the peer.

**Offline.** A request is written to `state/tray/requests/<id>.json` (and `<id>.jpg|png`) before anything else, at most three at a time ("network trouble is a prime reason to ask for help"). It is sent when the agent is connected and whenever it reconnects, and deleted when the server answers (a ticket or a final error). The tray waits up to 30 seconds for the ticket number, else it's told the request is queued. The last config is cached in `state/tray/config.bin`, so the card works offline.

**Consent.** A desktop session with consent asks `Tray::ask_consent(session, …)` first: the newest link for the target's session (Windows: the console session id; Linux: the display owner's uid) shows the prompt. No answer within the timeout denies. No link, or the link drops: the existing `WTSSendMessage` / zenity prompt is used. While a helper runs, every link gets a "technician connected" notice, and another when it ends.

**Restart.** A link whose `Hello.version` differs from the service's (an agent self-update replaced the binary) is sent `Restart`, and the tray re-executes itself from the binary on disk.

**Windows pipe.** Created with `first_pipe_instance` (if another process already owns the name the service refuses to serve under it), `reject_remote_clients`, and the DACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120083;;;IU)`: interactive users get read/write data, read attributes and synchronize, but not `FILE_CREATE_PIPE_INSTANCE`, so they can't stand up a second server instance. The tray opens the pipe with `CreateFileW` asking for exactly that access, and refuses a server whose process isn't in session 0.

## Protocol (`rmm-proto/src/tray.rs`, capability `tray`)

- `ServerMsg::TrayConfig(Config { enabled, product_name, icon_png, contact { name, phone, email, url, hours }, links, request_help, screenshot_default })`: on connect, after any policy change that reaches the agent (`policy::changed`), and after any branding write (`branding_changed`: the client's agents, or all for the instance).
- `AgentMsg::HelpRequest { request_id, user, session, subject, body, context { uptime_secs, ips, queued_secs }, screenshot_len }`, then `AgentMsg::HelpAttachment { request_id, offset, data, done }` in 256 KiB pieces. Kind indices 43 and 44 (`help_request`, `help_attachment`).
- `ServerMsg::HelpRequestResult { request_id, ticket_number, error }`.

Only agents listing `tray` get the server messages; older agents never see them, and an older server ignores the capability.

## Server (`src/helpdesk_agent.rs`)

- Requests with a screenshot are assembled in memory per (agent, request) until `done` (out-of-order or over-length pieces drop the assembly; the agent resends), at most three per agent, dropped after 10 minutes.
- **Idempotent** on `tickets.source_ref = request_id` with `(source, source_ref)` unique: a resend gets the existing ticket's number, a race between two connections is settled by the index.
- **20 a day per device** (tickets with source `agent` linked to it in the last 24 hours).
- The ticket is made like a portal request: client from the agent, site from the agent, board `company_settings.tray_board_id`, else `portal_board_id`, else the first board; priority 3; the request as the public first entry; source `agent`; the device in `ticket_agents`.
- **Contact.** When the account name (after any `DOMAIN\`) contains `@` and matches a contact's email in that client, the ticket is theirs. Otherwise the requester is "jsmith on HOST". Plain `DOMAIN\user` accounts aren't matched: the agent can't tell a UPN from the service side without asking a directory.
- **Context**: an internal note with the device, OS, signed-in user, uptime, addresses, how long it waited offline, and up to 20 open alerts.
- The screenshot is a ticket attachment (`screenshot.jpg|png`) on the first entry. If storing it fails, the ticket stays and a warning is logged.
- Audit `ticket.create` with `source: agent`, the agent, user and session; the board's new-ticket notifications and the live ticket event as for any ticket.

## Policy and settings

Module `tray`, single-instance, seed item `00000000-0000-4000-8000-000000000007` in All devices: `{ enabled: true, request_help: true, contact_card: true, screenshot_default: true, links: [] }`. Every field is overridable per set. Links: at most 10, a label of 1–60 characters and an `http(s)` URL (parsed, no spaces or quotes); the tray opens only `http(s)` links in any case. `0052` re-declares `policy_items_module_check` with 0035's list plus `disk_encryption`, `local_admin` (0038/0039, added in parallel) and `tray`.

`GET|PUT /settings/service-desk` gains `tray_board_id` (null: the portal's board). No new public API routes.

## UI

- Policies → a set → **Tray app** (`TrayForm.svelte`): the four switches and the link list.
- Tickets from a device show a "From device" badge in the header and "From device" as their source.
- Settings → Service desk: "Requests from the tray app go to".
- Settings → Branding: the preview's support card notes that the tray shows it.

## Choices made here

- **Linux `--background` link.** The plan had no persistent Linux process. The autostart entry runs one without any icon so consent prompts and notices appear in the user's own session through the tray, as on Windows; the launcher alone would make autostart pointless.
- **Contact name** on the card is the company name from Company settings (else the branded product name); phone, email, web and hours are the branding's support fields (client override first).
- **Identity**: the requester is the peer's account as the OS reports it; UPN matching only when that account name is itself an address (Entra-joined machines report `AzureAD\user@domain`).
- **Context** comes partly from the agent (uptime, addresses) and partly from the server (OS, open alerts), rather than the agent collecting alerts it doesn't have.
- **`tickets.source`** gains `agent` (the check constraint is re-declared in `0052`) besides the planned `source_ref`.
- Consent prompts through the Windows tray use user32's `MessageBoxTimeoutW` (exported but undocumented), falling back to a plain box; the service enforces the timeout either way.
- The metrics array has placeholders at 38–42 for the other tracks' kinds.

## Tests

- Unit: the IPC codec (split frames, oversized and malformed frames, the random-bytes fuzz), the limiter, size caps and image types, request persistence (three at most, restart, tampered file names), the service end over in-memory streams (offline queueing and resend in pieces, ticket numbers, the sixth request refused, policy off, consent only from the session's link, junk ends the connection), the service and a client over a real Unix socket with `SO_PEERCRED`, Unix peer names, Windows account formatting and the Run value, the policy validation, the context note, the MSI's Registry row and sequence, the deb's desktop entries, the proto round trip with an old peer.
- e2e `tray` (Linux, `RMM_E2E_ONLY=tray`): the headless CLI over a1's socket; the socket is `0666`; the config's defaults, then a client branding override reaching `--show-config`; a request with a 300 KB screenshot becomes a ticket with source `agent`, `source_ref`, the device, the attachment, the context note with the e2e's user, and the audit row; a request made while the server is stopped is kept on disk, arrives once after it restarts, and is forgotten; requests three to five go through and the sixth is refused; a blank subject is refused locally.
- Windows e2e section `tray`: `--show-config` and `--request` over the named pipe, the ticket and the `DOMAIN\user` note; the Run value after MSI install and gone after uninstall.

## Unproven here

The Win32 icon, menu, form, balloon and consent box; several sessions on a terminal server; UAC and the secure desktop; the zenity/kdialog dialogs on real desktops; Wayland (no screenshot by design). Listed in [windows-testing.md](windows-testing.md) §6a and roadmap block 1; the socket and pipe are in block 2's security review.
