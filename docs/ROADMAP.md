# Roadmap

Last reviewed 2026-11-24. Finished work has moved out: [FEATURES.md](FEATURES.md) summarises what each phase built, and the [CHANGELOG](../CHANGELOG.md) covers releases from `v0.1.1` on (the latest is `v0.2.0`, 2026-11-23).

## Where things stand

Everything built works end to end on Linux and is covered by unit tests, the e2e suite (`crates/rmm-server/tests/e2e.rs`), the Windows e2e on `windows-latest`, the `upgrade` and `restore-drill` jobs and the Playwright visual and accessibility tests. The biggest gap is still that **no Windows code path has run on a real Windows host**, and Windows is where most MSP fleets are. On the CI runner the Defender section skips the EICAR detection (the image excludes every drive from Defender scans); the [manual plan](design/windows-testing.md) covers it.

Design records: [PSA](design/psa.md), [endpoint protection](design/endpoint-protection.md), [antivirus](design/antivirus.md), [production readiness](design/production-readiness.md), [policy management](design/policies.md), [documentation and vault](design/documentation.md), [SSO](design/sso.md), [API](design/api.md), [fields](design/fields.md), [automations](design/automations.md), [audit/SIEM](design/audit-siem.md), [software](design/software.md), [network](design/network.md), [UI survey](research/rmm-ui-survey.md), [load test](research/load-test-2026-11.md).

## Next

In priority order. Block 1 waits on Windows hardware and the security review waits on a reviewer; work on the next block meanwhile.

### 1. Windows on real hosts

Follow the [manual plan](design/windows-testing.md) on Windows 10/11 and Server 2019/2022, and keep it running:

- [ ] Install and service on a real host: the `C:\ProgramData\RMM` ACL, the Program Files copy, SCM recovery actions, file logging, reinstall over a running service, MSI upgrade and repair.
- [ ] Self-update: service stop/start from the detached watchdog, and rollback.
- [ ] Jobs and shells (ConPTY, Job Objects), service list and control (`Win32_Service`), Event Log watchers (`wevtutil`).
- [ ] Patches: WUA scan and install, the `PSWindowsUpdate` fallback, reboot handling.
- [ ] Remote desktop: session-0 helper, `Winlogon`/UAC desktop switching, `SendSAS`, multi-monitor DPI, RDP sessions.
- [ ] Security: Defender (including the EICAR detection the runner skips), Security Center with a third-party product, passive mode; the sensor's process/network polling, quarantine, Windows Firewall isolation.
- [ ] Software deployment (winget, Chocolatey, MSI push) and automations on a real host.
- [ ] Uptime and backups on real hosts: ICMP through `IcmpSendEcho`, Windows Server Backup and Veeam event logs from real installs, Time Machine on a Mac (section 7a of the plan).
- [ ] Fix what breaks, and record the tested versions in the README.

### 2. Before the first real customer

- [ ] **Security review** by someone outside the project: agent/server protocol, enrollment, the update and content signing chain, session handling, per-client scoping, the shell and desktop relays, the client portal, the password vault (envelope encryption, reveal auditing, rate limits), API keys and SSO.
- [ ] **Try the integrations against the real services**, not stand-ins: AWS S3 (MinIO is done and in CI), Microsoft 365 over Graph, QuickBooks Online (sandbox company), Xero (demo organisation), OIDC with real Entra ID and Google tenants, and how real mail clients render our emails.

### 3. Gaps left by `v0.2.0`

- [ ] Alerts for failed software deployments.
- [ ] Automations whose `field_value` no longer matches a select field's choices never fire: warn when a choice is removed, or flag the automation.
- [ ] SNMP traps, LLDP neighbours and IPv6 scans for network discovery.
- [ ] SAML for technicians (OIDC only today).

### 4. Reach: more platforms

- [ ] **Windows real-time protection** (antivirus milestone 6): ETW for process starts and file writes instead of polling, scan on write and on start, and an AMSI provider for script content. Two earlier attempts stopped before any code was written; notes are in [design/antivirus.md](design/antivirus.md). Needs block 1's hosts to test on.
- [ ] **macOS as a supported platform**: launchd install, a signed and notarised `.pkg`, launchd services and the unified log, ScreenCaptureKit + `CGEvent` remote desktop, the Endpoint Security framework for the sensor. Pieces exist (patches, XProtect); the platform as a whole doesn't.
- [ ] Remote desktop on Wayland (GNOME Mutter RemoteDesktop/ScreenCast, then the portal for KDE/wlroots).
- [ ] Horizontal scaling: route hub messages over Postgres LISTEN/NOTIFY or NATS so several server nodes share agents. One node holds 10,000 agents, so do it when a customer needs more.

## Later

Worth doing, but not until the above is in place:

- **UI:** undo on cheap actions and optimistic toggles; a peek drawer from the agents list; favourites; configurable dashboard widgets; script version history.
- **Monitoring:** TimescaleDB if Postgres with rollups stops keeping up.
- **Patches:** Arch security data (`arch-audit`), Ubuntu Pro/ESM, Windows feature-update targeting.
- **Remote desktop:** clipboard sync and file drop; remote cursor shape; H.264 with hardware encoders and DXGI capture; WebRTC peer-to-peer with TURN fallback; session recording to object storage, a "being watched" indicator and view-only sessions.
- **Endpoint protection:** ClamAV on-access detections and the XProtect Remediator log; mass-encryption detection beyond decoys (fanotify, minifilter/ETW file events); rollback of Run keys, services and scheduled tasks; a measured performance budget on low-end hardware and an adversary-emulation lab run; a licensed hash/threat-intel feed; ingesting detections from other EDRs. Replacing Defender outright (minifilter, ELAM, MVI) needs a decision and money first.
- **PSA:** two-way calendar sync for the schedule; Stripe payment links on invoices; per-client purge of closed tickets for GDPR requests. Tax calculation stays with the accounting system by design.
- **Integrations:** HaloPSA, ConnectWise Manage and Autotask sync for MSPs keeping their own PSA; asset warranty lookups; M365 licence counts for per-user contracts.
