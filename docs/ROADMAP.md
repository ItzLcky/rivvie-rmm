# Roadmap

## Phase 1: Core (done)

- [x] Multi-tenant model (clients → sites → agents), RBAC, audit log
- [x] Token enrollment, per-agent secrets, outbound-only WebSocket transport
- [x] Metrics (CPU, memory, swap, disks, network, load) with 30-day history and charts
- [x] Inventory: hardware, disks, NICs, installed software (dpkg/rpm/pacman, Windows registry)
- [x] Script library and ad-hoc scripts (bash, sh, PowerShell, cmd, Python), bulk runs, offline queueing
- [x] Interactive web terminal (PTY / ConPTY)
- [x] systemd and Windows service install
- [x] Dashboard SPA

## Phase 2: Hardening (do before real customers)

Done:

- [x] Enrollment can't take over existing agents: a record is reused only when the agent proves its old secret; a bare token always creates a new record
- [x] Agent detects dead connections (100 s read timeout) and no longer waits for running jobs before reconnecting
- [x] Job lifecycle: in-flight jobs become `lost` on disconnect, server restart, or long past their timeout; queued jobs `expire` after `RMM_JOB_QUEUE_DAYS`
- [x] Agent refuses plain `http://` servers except localhost unless `--insecure`
- [x] Security headers: `frame-ancestors 'none'`, X-Frame-Options, nosniff, Referrer-Policy, HSTS when the public URL is https
- [x] systemd unit: dropped `MemoryMax=128M`/`Nice=10`, which every script and shell inherited
- [x] Windows: `C:\ProgramData\RMM` restricted to SYSTEM and Administrators (on enroll and every service start); job scripts written there instead of the shared temp dir
- [x] Windows: service binary copied to `C:\Program Files\RMM`, SCM restart-on-failure, file logging to `C:\ProgramData\RMM\logs\agent.log`
- [x] Account management: change password (signs out your other sessions), admin password reset (signs them out everywhere), re-enable users, list and revoke sessions. Sessions now expire after `RMM_SESSION_IDLE_HOURS` (default 12) of inactivity, within the 7-day cap.
- [x] Company settings page (admins only): company name shown in the sidebar, sign-in page and tab title; session idle timeout override

To do:

- [ ] Integration tests: Postgres in CI, a real agent driven against the server. Start from the manual e2e run: enrollment reuse/takeover, `lost`/`expired` jobs, headers.
- [ ] Rate-limit `/auth/login` and enrollment. Behind Caddy, key on `X-Forwarded-For` only when it comes from a trusted proxy.
- [ ] TOTP 2FA for dashboard users; enforce it on admin accounts
- [ ] Per-client access control for technicians (`user_clients` table) and an optional client-portal role. Touches every query; decide first whether scripts are global or per client.
- [ ] **Test the Windows agent on real hosts** (Windows 10/11, Server 2019/2022). CI compiles it but nobody has run it. Check the ACL, the Program Files copy, the recovery actions and logging first.
- [ ] Windows: run jobs and shells inside a Job Object so timeouts and session close kill the whole process tree (Unix jobs already use process groups; shells on both OSes only kill the direct child)
- [ ] Agent self-update: signed binaries (ed25519), staged download, swap, rollback if the new binary doesn't reconnect within N seconds. Keep the signing key off the server (it already controls agents via scripts; signing protects the download path). Rollback needs a watchdog outside the new binary, and restarting under systemd's default `KillMode=control-group` kills running jobs.
- [ ] MSI installer (WiX) and `.deb`/`.rpm` packages with the server URL and token baked in. Default baked tokens to an expiry and a `max_uses` limit.
- [ ] Agent buffers job results across reconnects instead of losing them (today they become `lost`)
- [ ] Script-src CSP via SvelteKit's hash-based `kit.csp`
- [ ] Postgres backups in the deploy stack

## Phase 3: Monitoring and alerting

- [ ] Alert policies per client or site: offline > N min, CPU/mem/disk thresholds held for M min, service stopped, failed job
- [ ] Notification channels: email (SMTP), webhook, Slack/Teams
- [ ] Service monitoring: systemd units / Windows services. Inventory them, alert on state, start/stop/restart from the UI.
- [ ] Event log / journald watchers with match rules
- [ ] Scheduled scripts (cron-style) per client or site, with output retention
- [ ] Move `agent_metrics` to TimescaleDB, or add hourly rollups, once fleets reach thousands of agents

## Phase 4: Patch management

Agent side, behind a `PatchProvider` trait:

| OS | Scan | Install |
|---|---|---|
| Windows | `IUpdateSearcher` via the Windows Update Agent COM API (`windows` crate); fall back to `PSWindowsUpdate` | `IUpdateInstaller`; reboot handling via `IUpdateInstaller::RebootRequiredBeforeInstallation` |
| Debian/Ubuntu | `apt-get -s upgrade` / `apt list --upgradable` (after `apt-get update`) | `apt-get -y install --only-upgrade <pkgs>` with `DEBIAN_FRONTEND=noninteractive` |
| RHEL/Fedora | `dnf check-update --refresh` / `dnf updateinfo list --sec` | `dnf -y upgrade <pkgs>` |
| Arch | `checkupdates` | `pacman -Syu --noconfirm` (all-or-nothing) |
| macOS | `softwareupdate -l` | `softwareupdate -i` |

Protocol: `ServerMsg::PatchScan`, `PatchInstall { ids, reboot_policy }` → `AgentMsg::PatchScanResult { updates: [{ id, title, kb, severity, size, requires_reboot }] }`, `PatchProgress`, `PatchResult`.

Server: `patches` table (per agent and update), patch policies (auto-approve by severity/category, deferral days, maintenance window per site, reboot policy), approval UI, compliance dashboard (% patched per client).

## Phase 5: Remote desktop

The hardest piece. Plan:

1. **Capture** (agent, a separate `rmm-desktop` helper process):
   - Windows: DXGI Desktop Duplication. The agent runs as SYSTEM in session 0, so it must launch the helper *into the active console session* (`WTSGetActiveConsoleSessionId` + `WTSQueryUserToken` + `CreateProcessAsUserW`) to see the desktop, the UAC secure desktop, and the login screen.
   - Linux: PipeWire screencast portal (Wayland) or XShm (X11).
   - macOS: ScreenCaptureKit (needs the Screen Recording TCC permission).
2. **Encode:** H.264 via hardware encoders (Media Foundation / VA-API / VideoToolbox) with an `openh264` software fallback. Send only changed frames, with an adaptive bitrate.
3. **Transport:** WebRTC (the `webrtc-rs` crate) so video goes peer-to-peer when possible, with the server as signalling and a TURN relay fallback. Simpler v1: send encoded frames over the existing WebSocket, relayed by the server, and decode in the browser with WebCodecs (`VideoDecoder`).
4. **Input:** `SendInput` (Windows), `uinput` or XTest (Linux), `CGEvent` (macOS). Map browser keyboard and mouse events, including a Ctrl+Alt+Del button (`SendSAS` on Windows).
5. **Extras:** clipboard sync, multi-monitor selection, an end-user consent prompt option per client, session recording to object storage.

An interim option is to bundle an existing RustDesk server/client and broker sessions from the dashboard. That's useful for early customers while native remote desktop gets built.

## Phase 6: Nice to have

- File browser and transfer (upload/download over the agent socket in chunks)
- Process list / kill and a services panel
- Software deployment (winget / choco / apt packages, MSI push)
- Asset warranty lookups, custom fields, tagging, saved agent filters
- PSA integrations (ticketing), API keys for automation, a public REST API with OpenAPI docs
- Horizontal scaling: route hub messages over Postgres LISTEN/NOTIFY or NATS so several server nodes can share agents
