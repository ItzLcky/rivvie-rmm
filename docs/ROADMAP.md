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

- [ ] **Test the Windows agent on real hosts** (Windows 10/11, Server 2019/2022). CI compiles it but nobody has run it.
- [ ] Windows: run jobs inside a Job Object so a timeout kills the whole process tree (Unix already uses process groups)
- [ ] Windows: lock the `C:\ProgramData\RMM` ACL to SYSTEM and Administrators when installing
- [ ] Agent self-update: signed binaries (ed25519), staged download, swap, rollback if the new binary doesn't reconnect within N seconds
- [ ] MSI installer (WiX) and `.deb`/`.rpm` packages with the server URL and token baked in
- [ ] TOTP 2FA for dashboard users; enforce it on admin accounts
- [ ] Per-client access control for technicians (`user_clients` table) and an optional client-portal role
- [ ] Rate-limit `/auth/login` and enrollment
- [ ] Integration tests: spin up Postgres in CI and drive a real agent against the server (mirroring the manual e2e run)

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
