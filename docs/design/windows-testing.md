# Windows: what CI covers and a manual test plan for real hosts

The `e2e-windows` job (`crates/rmm-server/tests/e2e_windows.rs`, on GitHub's `windows-latest`,
which is Windows Server with no console user, one monitor and no third-party antivirus) runs:

| Section | What it proves |
|---|---|
| `base` | MSI install, service and recovery actions, data-directory ACL, PowerShell and cmd jobs, Job Object tree kill, results across a service restart, service list, MSI upgrade over itself |
| `shell` | A ConPTY terminal through the shell relay: command and output, resize, closing kills what was started from it, `exit` ends the session |
| `eventlog` | `wevtutil` watcher: an error from `eventcreate` and from `Write-EventLog` opens an alert; an information event does not |
| `patches` | A WUA scan returns a result or a Windows Update connectivity error, never an agent-side failure. Installs nothing |
| `defender` | `Get-MpComputerStatus` reporting, a signature update, and a detection of the EICAR file |
| `sensor` | The sensor starts, reports process telemetry and a behaviour detection, quarantines and restores a flagged file |
| `update` | Signed self-update: the detached watchdog stops and starts the service, a build that never confirms is rolled back after 120 s, then an update that confirms |

Run a subset on a throwaway VM with `RMM_E2E_ONLY=shell,eventlog` (or `RMM_E2E_SKIP=sensor`);
the module docs in `e2e_windows.rs` list the environment (the `update` section needs a second,
newer agent build and the release key).

Everything below needs a person, because it needs hardware, a signed-in user, another vendor's
software or the ability to break the network. Run it on each of the **four targets**:

- Windows 10 22H2 (workstation)
- Windows 11 24H2 (workstation)
- Windows Server 2019
- Windows Server 2022

Use a snapshot-able VM (Hyper-V or similar) so a failed step can be rolled back, and a test
server (the RMM server with a throwaway client and site) you can reach from the VM. Build the
agent as a release (`cargo build --release -p rmm-agent --target x86_64-pc-windows-msvc`), put
it in the server's `RMM_AGENT_DIR` and download the MSI from *Sites → Enrollment tokens*.

Record the outcome per target in the table at the end. A step that fails is a bug: write what you
saw, `C:\ProgramData\RMM\logs\*.log`, and the Event Viewer entry if there is one.

## 1. Install and service

1. As an administrator, run `msiexec /i rmm-agent.msi /qn /l*v install.log`.
   - `sc query RmmAgent` says RUNNING; `sc qc RmmAgent` shows start type AUTO_START, account LocalSystem.
   - `C:\Program Files\RMM\rmm-agent.exe` exists. The agent is online in the console within a minute.
   - `icacls C:\ProgramData\RMM` lists only SYSTEM and Administrators (no Users, Everyone, Authenticated Users), and `agent.toml` inside is not readable as an ordinary user (`runas /user:<standard user> cmd`, then `type`).
   - `C:\ProgramData\RMM\logs\agent.log` is being written; `install.log` there ends `ok: enrolled as ...`.
2. `sc qfailure RmmAgent` shows restart actions at 5 s, 30 s and 60 s and "failure actions on non-crash failures". Kill the process (`taskkill /f /im rmm-agent.exe`): the service is RUNNING again within ~10 s and the agent reconnects. Do it three times in a row; the third restart takes 60 s.
3. Stop it cleanly (`sc stop RmmAgent`): no restart (a clean stop is not a failure). Start it (`sc start RmmAgent`). Reboot the machine: the service starts by itself and the agent comes back without anyone logging in.
4. Reinstall over a running service: run `rmm-agent.exe enroll --server <url> --token <token> --install --keep-existing` from a Downloads folder as an administrator while the service runs. The copy under Program Files is replaced, the service is running afterwards, the agent keeps its identity (same agent in the console, no duplicate).
5. As a standard user, confirm the binary under Program Files cannot be modified (`echo x >> "C:\Program Files\RMM\rmm-agent.exe"` is denied).
6. Install on a machine with a space in the user name and a non-English display language: the install and `install.log` do not depend on either.
7. Windows installed on a drive other than C: (a VM with Windows on D: is enough): install, then check quarantine of a file under `D:\Windows\System32` is refused ("operating system file").

## 2. MSI upgrade, repair and uninstall

1. Install version A, then double-click or `msiexec /i` a package of the same product from a newer server build. Exactly one "RMM Agent" in *Apps and features*; the service is RUNNING; the agent keeps its identity; the enrollment token's use count did not change.
2. Downgrade (install an older package over a newer one): it replaces the newer one (the upgrade table covers every version).
3. Repair: delete `C:\Program Files\RMM\rmm-agent.exe` while the service is stopped, run `msiexec /fa rmm-agent.msi /qn`: the file returns and the service runs. Then clear the recovery actions (`sc failure RmmAgent reset= 0 actions= ""`) and repair again; note whether they come back (only the binary is a repaired component, so probably not) and, if not, that re-running the MSI install (not repair) restores them.
4. Install with the MSI while a user has a PowerShell terminal open through the console (shell relay): the install completes, the terminal ends, nothing is left running from the old binary.
5. Uninstall (`msiexec /x`): service gone, `rmm-agent.exe`, `rmm-agent.old.exe` and `rmm-agent.new.exe` gone from Program Files, `C:\ProgramData\RMM\agent.toml` kept, agent shows offline. Reinstall: it re-enrolls under the same identity.
6. Branding (Settings → Branding, [design](branding.md)): with a product name and a square icon set, download the MSI. *Apps and features* lists "<product> Agent" with the icon; `services.msc` shows the display name "<product> Agent" (service id still `RmmAgent`); `agent.toml` has `product_name`. Install it over an unbranded install: one entry, renamed. Clear the branding and upgrade again: note whether the service keeps the branded name (it does until `product_name` is removed from `agent.toml`). The remote-desktop consent prompt's title starts with the product name.
7. An install with no network to the server: the install itself succeeds (`install.log` says enrollment failed), the service is installed, and enrolling later with `rmm-agent enroll` works.

## 3. Self-update

CI covers the signed path and a rollback on a server image. On real hosts, add what only they have:

1. Build two releases (A: older, B: newer), sign B with `rmm-sign` and put it in `RMM_AGENT_DIR`. From the console, update the agent. In `C:\ProgramData\RMM\logs\update.log` the watchdog logs the swap and "new version confirmed"; the agent shows B.
2. Antivirus in the way: with Defender real-time on (and with a third-party AV, section 7), the update still completes. If the `.new` file is held by a scanner the swap retries (up to 5 s); note any update that needs longer.
3. Interrupt it: start an update, then power the VM off hard while the watchdog is waiting for confirmation (after the service restarted). On boot the new agent starts as the service; the update state ends `completed`. Repeat powering off right after the service stops (before the swap): after boot the old binary is still in place and still works (`rmm-agent.new.exe` may remain; the next update replaces it).
4. A running patch install or job: start a long job, offer an update; it waits ("waiting for running jobs") and applies when the job ends.
5. A broken update: sign a build that exits immediately. The service fails to start, the watchdog restores the old binary within a minute, the console shows `rolled_back` with the reason, and the same version is not offered again automatically.
6. A remote desktop session open during the update: the helper process exits and the swap still succeeds.

## 4. Jobs, shells, services, Event Log

1. PowerShell and cmd jobs: Windows PowerShell 5.1 only, and where PowerShell 7 is installed too. Non-ASCII output (`Write-Output "héllo ✓"`) round-trips. A script that reads from stdin gets EOF, not a hang.
2. A timeout kills the whole tree (Job Object): script starts `notepad` and a child PowerShell that sleeps; after the timeout neither remains (`Get-Process notepad`).
3. A terminal from the console: arrow keys, tab completion, Ctrl+C (stops a `ping -t`), resizing the browser window resizes the console (`$Host.UI.RawUI.WindowSize`), `exit` ends the session in the console. Open a terminal, start `notepad` from it, close the browser tab: notepad is gone. Open ten terminals at once, close them: no `powershell.exe` is left behind.
4. Services page: the list shows what `Get-Service` shows (names, display names, state, start type, the account). Stop, start and restart a harmless service (Print Spooler) from the console, and a service that depends on others (the dependents are listed, the stop fails with the SCM's message and the console shows it). A service name with a space or `$` (`MSSQL$SQLEXPRESS` on a box with SQL Express) works.
5. Event Log watchers: an alert policy with `channels: ["System"]`, `event_ids: [7036]`, `min_level: info`, `pattern: "Print Spooler"`. Stop the spooler: one alert within ~35 s. A policy with no channel reads System and Application. A policy on the `Security` channel for event 4625 (failed logon): fail a logon (wrong password at `runas`) and the entry arrives with the right source ("Microsoft-Windows-Security-Auditing"). A localized Windows (German): the message text is the localized one, matched by a localized pattern; event ids still match.
6. The Event Log's own limits: write 50 matching events in a minute; the watcher sends 20 and reports the rest as suppressed.
7. Script parameters ([design](script-params.md)): a PowerShell script `Write-Output "[$env:RMM_PARAM_TARGET]"` and a cmd script `echo [%RMM_PARAM_TARGET%]` with the value `$(calc) & calc "%PATH%"` print it verbatim and start nothing; `$env:RMM_AGENT_HOSTNAME` is the machine's name; a secret parameter's value is printed by the script but `jobs.params` shows `•••`; a value of 8 KiB arrives whole, a set of values over 24 KiB is refused by the agent with an error naming no value.

## 5. Patches

1. Scan: *Patches → Scan now* on a machine with updates pending. The list matches *Settings → Windows Update* (titles, KB numbers, security vs other, drivers listed as drivers). Categories and severity are right for a cumulative update, a .NET update, a Defender definition update (`definition`) and a driver.
2. Install one approved update. Stages move from refreshing to downloading to installing; the result is recorded per update; the history shows it. A reboot-required update leaves `reboot_pending` true and the console shows "restart pending" (compare `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`).
3. Reboot policy: with "if required" the machine restarts after an install that needs it (inside the maintenance window), with "always" after every install that changed something, and with "never" it doesn't (the restart stays pending and visible). Check that a user's unsaved work gets the usual Windows shutdown warning.
4. Failure handling: disconnect the network during the download. The run ends in an error, the update is retried by policy, and the scan afterwards still works. A WSUS-managed machine (`HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` with `WUServer`) scans against its WSUS. A machine with Windows Update disabled by policy reports the error rather than an empty list.
5. The fallback: on a machine where COM activation fails (revoke it with a test policy, or run the agent as a user that cannot create `UpdateSession`), with the `PSWindowsUpdate` module installed the agent logs "using PSWindowsUpdate" and its scan and install work; without the module it reports the WUA error.
6. A scan during an install, an install while Windows Update is already installing updates (the two queue or fail cleanly, never double-install).
7. Server 2019 and 2022: a scan finds the monthly cumulative update; installing it with "restart: never" leaves the pending restart visible, and the next restart clears it in the console within one heartbeat.

## 6. Remote desktop

Needs a signed-in console user (a VM console session), not just the agent.

1. Session 0: with the user signed in, open *Remote desktop*. The consent prompt appears on the user's desktop (it comes from the SYSTEM helper placed in the console session); allowing shows the desktop; denying ends the session with the reason. With nobody signed in, the log says "nobody is signed in to ask; starting without consent" if the policy permits that and shows the sign-in screen.
2. Input: type with the keyboard (letters, shifted symbols, `AltGr` on a German layout, an accented character through the text path), mouse buttons and wheel (vertical and horizontal), drag a window.
3. UAC: run something that prompts (right-click → Run as administrator). The remote view switches to the secure desktop (the screen darkens but is visible), and clicking Yes works. Without the switch the view freezes: that is the bug to report.
4. Sign-in and lock screens: lock the machine (Win+L) and keep the session open: the lock screen is visible and typing the password signs in. Sign out: the session follows to the sign-in screen.
5. Send Ctrl+Alt+Del from the console's button: the Windows Security screen appears (`SoftwareSASGeneration` is set to allow services to send it; the agent logs when it sets it). On a machine where Group Policy forces it to 0, the button reports the failure.
6. Monitors and DPI: two monitors at different scaling (100% and 150%): the monitor picker lists both with the right sizes, switching works, mouse positions land where clicked on the secondary monitor, including one placed to the left of or above the primary (negative coordinates). Change a monitor's scale or resolution mid-session: the view follows without a restart.
7. RDP: connect to the machine over RDP as a user. The console's session finds the active session (RDP sessions are session 2 or higher, not the physical console; check which one it picks and that it is the one a person is using). Disconnect the RDP session without signing out (the session stays, disconnected): the remote desktop either shows it or reports that nobody is watching. Reconnect and confirm the helper follows. Fast user switching: two users signed in, the one on the console is the one shown.
8. Frame rate and CPU: a video playing full screen at 1080p stays above ~10 fps over a LAN and the agent's CPU stays reasonable (note the number). Closing the session ends the helper process (`Get-Process rmm-agent` shows only the service).
9. The relay's other half: file browser and transfer to a path with spaces and non-ASCII characters; a 1 GB upload; browsing `C:\Users` as SYSTEM.

## 7. Security

1. Defender, normal mode: the Security tab shows enabled, real-time, tamper protection, the signature version and age, and the last quick and full scan. Run a quick scan, a full scan and a signature update from the console; each ends with the real result. Drop the EICAR file in `C:\Users\Public`: the detection appears with the right name, severity and resource, an alert opens by policy, and clearing the threat (`Remove-MpThreat`) resolves it.
2. Passive mode: install a third-party antivirus (Sophos, ESET or Bitdefender trial). Defender goes to passive or off. The console shows the other product as the protection, Defender as "passive (another antivirus is primary)", and no "protection off" alert. Scans and updates for the third-party product are not offered (the console says it is not controlled from here).
3. Security Center: on a workstation, disable the third-party product's real-time protection: the console shows protection off and the alert fires; re-enable: it clears. Let its definitions age: "signatures out of date". Uninstall the product: Defender returns to normal mode and is reported again. On Server editions Security Center does not exist; the console must still show Defender and no error.
4. Tamper protection: turn it on and off in Windows Security and confirm the console follows.
5. Sensor: enable the sensor by policy. Process telemetry shows processes started by users and services, with command lines and parents; short-lived processes can be missed (note how often `cmd /c exit` is seen). Network connections appear for a browser session. Run `rmm-sign`-signed content that flags a marker file: scan a folder, the file is quarantined (the original gone, the quarantine list shows it), restore puts it back byte for byte and keeps the ACL of the folder. A file in `C:\Windows\System32` is never quarantined automatically. A file locked by another process fails with a clear message and nothing is lost.
6. The sensor beside Defender: both running, the sensor's scans do not slow the machine visibly; stopping the sensor (policy off) removes the process within seconds; killing it (`taskkill /f`) is noticed and it comes back, with an alert if so configured.
7. Windows Firewall isolation: from the console, isolate the machine. Within seconds: the browser cannot reach the internet, the agent stays connected to the server (the console still shows it online and can run a job), DNS and DHCP still work. `netsh advfirewall show allprofiles` shows block inbound and outbound, and `RMM-isolation-*` rules exist. Reboot while isolated: still isolated when the agent starts (and the console's job still reaches it). Un-isolate: all three profiles return to the policy they had before (compare with the export `C:\ProgramData\RMM\isolation-firewall.wfw` taken first), the isolation rules are gone, and a custom firewall rule you made before is enabled again. Isolate twice in a row, then un-isolate: the original policy comes back, not the isolated one. A server on a changing IP (a DNS name that resolves differently): the agent re-resolves while isolated and stays connected. With Group Policy managing the firewall, note what wins.
8. Triage and response: kill a process tree from the console (a `ping -t` started from cmd); collect a triage package: it lists processes, services, connections and autoruns and downloads.

## Wake-on-LAN (any OS, real network)

The e2e test only proves the packet bytes reach a socket on loopback. On a real LAN with two machines at one site (one online with the agent, one with Wake-on-LAN enabled in its BIOS/UEFI and NIC driver, shut down or asleep):

1. Wake the sleeping machine from its page: it powers on and the agent reconnects. Repeat from S5 (shut down), S3 (sleep) and S4 (hibernate); Windows "Fast startup" often blocks waking from shutdown, note it.
2. Sender on Windows, Linux and macOS in turn (the directed broadcast and `255.255.255.255` both go out; note which interface the packet left on with Wireshark).
3. A target on another VLAN than the sender: expected to fail on most switches (directed broadcasts are dropped); note whether it does, and that the designated agent on the target's VLAN works.
4. A patch policy with an install window opening in 20 minutes and `wake_before_minutes` 30, an approved update and the machine asleep: it wakes once, installs in the window, and isn't woken again for 12 hours.

## 7a. Uptime and backups

1. Uptime from a Windows agent: a ping monitor of the gateway (`IcmpSendEcho`) answers with a round trip; a ping of an address that doesn't exist fails with "no reply" within the timeout. HTTPS and TLS monitors of an internal site with a certificate from the domain's CA read as trusted (the Windows root store); a self-signed one as untrusted. A DNS monitor without a server uses the adapter's resolvers.
2. Windows Server Backup: on a server with a schedule, after one good and one failed run (unplug the target disk), the Backups card shows the right last success and result, from `Get-WBSummary`; with the cmdlets removed, the same from the event log. Installed and never run: no job, no error.
3. Veeam Backup & Replication and Veeam Agent for Windows: event 190 for a successful, a warning and a failed job gives the right name and result per job (the fixtures in `crates/rmm-agent/src/checks/backup/fixtures/` were written from documentation, not recorded: replace them with real exports). `auto` finds Veeam by its service.
4. A `file_age` source on a UNC path (`\\nas\backups`) as SYSTEM: what the service account can and can't read.
5. macOS (not Windows, but nowhere else to note it): Time Machine to a local disk and to a network destination, `tmutil latestbackup` and `tmutil status` while a backup runs.

## 7c. Identity: Active Directory on a domain controller

The e2e drives a fake directory; none of the PowerShell has run against a real DC. On a lab domain (one DC is enough; two to see replication), with the agent installed on a DC:

1. The agent lists `identity_ad` in its capabilities (`ProductType` `LanmanNT`); a member server and a workstation don't.
2. Add the client's AD directory and sync: every user and group appear, with last logon, password set and expiry (a "never expires" account shows none), locked accounts, `adminCount` users and Domain Admins members as privileged, and membership. Change a user in ADUC and sync again: a delta picks it up. Delete a user: it's marked gone after the next full sync (edit and save the directory to force one).
3. Lock an account (bad passwords), unlock it from the console; with two DCs, note how long until the other DC sees it.
4. Reset to the vault and shown once; sign in with it and get asked to change it. A fine-grained password policy (or the domain policy's length) refusing a short typed password gives the directory's message. Check the ActiveDirectory module's event logs and PowerShell script block logging (event 4104) for whether the password appears anywhere: it is in the stdin JSON, not the script, but logging policies vary.
5. Disable, enable, remove from groups (including a group in another domain of the forest, expected to fail with a message).
6. The built-in Administrator and krbtgt are refused even when the server is made to ask (send the op from a debug build).
7. Windows PowerShell 5.1 on Server 2016, 2019, 2022 and 2025.

## 7b. Disk encryption and local admin rotation

The CI runner has no BitLocker and isn't domain-joined; these need real hosts ([disk-encryption](disk-encryption.md), [local-admin](local-admin.md)).

1. BitLocker on a TPM laptop (Windows 11 Pro): `C:` reports `encrypted` with TPM and a recovery password; with escrow on, the vault gets `BitLocker recovery: HOST C:` and its reveal matches `manage-bde -protectors -get C:`. Rotate from the Inventory tab: a new numerical password replaces the old one on the machine and in the vault (the old one in its history). Suspend (`manage-bde -protectors -disable C:`): `suspended`, and the alert after the grace period; resume clears it.
2. A data drive with only a startup key and `add_recovery_protector` on: a recovery password is added and escrowed. With the GPO "Do not allow 48-digit recovery password" set: the refusal shows on the volume and isn't retried for a day.
3. Encryption in progress (`manage-bde -on D:`): `encrypting` with a percentage, no alert. A USB disk with BitLocker To Go: not listed.
4. Windows Home and Server without the BitLocker feature: fixed drives listed as unencrypted, no error. A non-English Windows where CIM is blocked: the `manage-bde` fallback (English parser) returns nothing; note what it shows.
5. Local admin rotation on a domain-joined workstation: the account is local, rotation works, and a domain account of the same name is untouched. On a domain controller: `unsupported`.
6. Windows LAPS on the same machine managing `rmmadmin` (`AdministratorAccountName`): `conflict` and the alert; managing only the built-in Administrator: no conflict.
7. A localised Windows (German, French): the account joins *Administratoren*/*Administrateurs* (looked up by SID). A local password policy stricter than the default (length 24): the failure message names the policy, the device keeps its previous password.
8. Linux as root (Ubuntu with `sudo`, Rocky with `wheel`): the account is created, can `sudo`, and `chpasswd` sets the vault's password; on a host without `chpasswd`: `unsupported`.

## 8. Fix what breaks, record versions

For each failed step, fix it with a test that reproduces it (unit tests against recorded output where the failure is parsing, the e2e where it is behaviour). Record in the README's Windows line which versions passed.

| Target | Date | Sections 1-8 pass | Notes |
|---|---|---|---|
| Windows 10 22H2 | | | |
| Windows 11 24H2 | | | |
| Windows Server 2019 | | | |
| Windows Server 2022 | | | |
